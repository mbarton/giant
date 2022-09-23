package utils.auth.providers

import model.frontend.user._
import model.user._
import play.api.libs.json.{JsBoolean, JsNumber, JsValue}
import play.api.mvc.{AnyContent, Request}
import services.DatabaseAuthConfig
import services.users.UserManagement
import utils.Epoch
import utils.attempt._
import utils.auth.totp.{SecureSecretGenerator, Totp}
import utils.auth.webauthn.WebAuthn
import utils.auth._

import scala.concurrent.ExecutionContext

/**
  * A UserAuthenticator implementation that authenticates a valid user based on credentials stored in the local database
  */
class DatabaseUserProvider(val config: DatabaseAuthConfig, passwordHashing: PasswordHashing, users: UserManagement,
                           totp: Totp, ssg: SecureSecretGenerator, passwordValidator: PasswordValidator, tfa: TwoFactorAuth)
                          (implicit ec: ExecutionContext)
  extends UserProvider {

  override def clientConfig: Map[String, JsValue] = Map(
    "require2fa" -> JsBoolean(config.require2FA),
    "minPasswordLength" -> JsNumber(config.minPasswordLength)
  )

  override def authenticate(request: Request[AnyContent], time: Epoch): Attempt[PartialUser] =
    authenticateUser(request, time, RequireRegistered).map(_.toPartial)

  override def genesisUser(request: JsValue, time: Epoch): Attempt[PartialUser] = {
    for {
      userData <- request.validate[NewGenesisUser].toAttempt
      encryptedPassword <- passwordHashing.hash(userData.password)
      _ <- passwordValidator.validate(userData.password)
      // We will immediately register after creating
      user = DBUser(userData.username, None, None, invalidationTime = None, registered = false)
      created <- users.createUser(user, UserPermissions.bigBoss)
      registered <- users.registerUser(userData.username, userData.displayName, Some(encryptedPassword))
    } yield registered.toPartial
  }

  override def createUser(username: String, request: JsValue): Attempt[PartialUser] = {
    for {
      wholeUser <- request.validate[NewUser].toAttempt
      _ <- if (username == wholeUser.username) Attempt.Right(()) else Attempt.Left(ClientFailure("Username in URL didn't match that in payload."))
      _ <- passwordValidator.validate(wholeUser.password)
      hash <- passwordHashing.hash(wholeUser.password)
      user <- users.createUser(
          DBUser(wholeUser.username, Some("New User"), Some(hash), invalidationTime = None, registered = false),
        UserPermissions.default
      )
    } yield user.toPartial
  }

  override def registerUser(request: JsValue, time: Epoch): Attempt[Unit] = {
    for {
      userData <- request.validate[UserRegistration].toAttempt
      _ <- passwordHashing.verifyUser(users.getUser(userData.username), userData.previousPassword, RequireNotRegistered)
      _ <- passwordValidator.validate(userData.newPassword)
      newHash <- passwordHashing.hash(userData.newPassword)
      _ <- tfa.check2fa(userData.username, userData.tfa, time, RequireNotRegistered)
      _ <- users.registerUser(userData.username, userData.displayName, Some(newHash))
    } yield ()
  }

  override def removeUser(username: String): Attempt[Unit] = {
    users.removeUser(username)
  }

  override def updatePassword(username: String, newPassword: String): Attempt[Unit] = {
    for {
      passwordHash <- passwordHashing.hash(newPassword)
      _ <- passwordValidator.validate(newPassword)
      _ <- users.updateUserPassword(username, passwordHash)
    } yield ()
  }

  override def get2faRegistrationParameters(request: Request[AnyContent], time: Epoch, instance: String): Attempt[TfaRegistrationParameters] = for {
    user <- authenticateUser(request, time, AllowUnregistered)
    username = user.username

    existingTfa <- users.getUser2fa(username)

    inactiveTotpSecret = existingTfa.inactiveTotpSecret.getOrElse(ssg.createRandomSecret(totp.algorithm))
    // It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user’s account
    // https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
    webAuthnUserHandle = existingTfa.webAuthnUserHandle.getOrElse(WebAuthn.UserHandle.create(ssg))
    // Challenges SHOULD therefore be at least 16 bytes long.
    // https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
    webAuthnChallenge = existingTfa.webAuthnChallenge.getOrElse(WebAuthn.Challenge.create(ssg))

    newTfa = existingTfa.copy(
      inactiveTotpSecret = Some(inactiveTotpSecret),
      webAuthnUserHandle = Some(webAuthnUserHandle),
      webAuthnChallenge = Some(webAuthnChallenge)
    )

    _ <- users.setUser2fa(username, newTfa)
  } yield {
    val totpSecret = inactiveTotpSecret.toBase32

    TfaRegistrationParameters(
      totpSecret = totpSecret,
      totpUrl = s"otpauth://totp/$username?secret=$totpSecret&issuer=${config.totpIssuer}%20($instance)",
      webAuthnUserHandle = WebAuthn.toBase64(webAuthnUserHandle.data),
      webAuthnChallenge = WebAuthn.toBase64(webAuthnChallenge.data),
    )
  }

  override def get2faConfig(request: Request[AnyContent], time: Epoch): Attempt[TfaUserConfiguration] = for {
    user <- authenticateUser(request, time, RequireRegistered)
    username = user.username

    user2fa <- users.getUser2fa(username)
    user2faConfig <- buildAndSave2faConfiguration(username, user2fa)
  } yield user2faConfig

  override def register2faMethod(request: Request[AnyContent], time: Epoch, registration: TfaRegistration): Attempt[TfaUserConfiguration] = for {
    user <- authenticateUser(request, time, AllowUnregistered)
    username = user.username

    before <- users.getUser2fa(username)
    after <- validateRegister2faMethod(before, registration, time)

    user2faConfig <- buildAndSave2faConfiguration(username, after)
  } yield user2faConfig

  private def authenticateUser(request: Request[AnyContent], time: Epoch, registrationCheck: RegistrationCheck): Attempt[DBUser] = {
    for {
      formData <- request.body.asFormUrlEncoded.toAttempt(Attempt.Left(ClientFailure("No form data")))
      username <- formData.get("username").flatMap(_.headOption).toAttempt(Attempt.Left(ClientFailure("No username form parameter")))
      password <- formData.get("password").flatMap(_.headOption).toAttempt(Attempt.Left(ClientFailure("No password form parameter")))
      tfaChallengeResponse = formData.get("tfa").flatMap(_.headOption).map(TotpCodeChallengeResponse)
      dbUser <- passwordHashing.verifyUser(users.getUser(username), password, registrationCheck)
      _ <- tfa.check2fa(username, tfaChallengeResponse, time, registrationCheck)
    } yield dbUser
  }

  private def buildAndSave2faConfiguration(username: String, existing2fa: DBUser2fa): Attempt[TfaUserConfiguration] = {
    if(config.require2FA && existing2fa.activeTotpSecret.isEmpty) {
      Attempt.Left(SecondFactorRequired("2FA enrollment is required"))
    } else {
      val challenge = WebAuthn.Challenge.create(ssg)
      val new2fa = existing2fa.copy(webAuthnChallenge = Some(challenge))

      users.setUser2fa(username, new2fa).map { _ =>
        TfaUserConfiguration(
          totp = config.require2FA,
          webAuthnCredentialIds = new2fa.webAuthnPublicKeys.map { k => WebAuthn.toBase64(k.id) },
          webAuthnChallenge = WebAuthn.toBase64(challenge.data)
        )
      }
    }
  }

  private def validateRegister2faMethod(before: DBUser2fa, registration: TfaRegistration, time: Epoch): Attempt[DBUser2fa] = {
    registration match {
      case TotpCodeRegistration(code) =>
        for {
          secret <- Attempt.fromOption(before.inactiveTotpSecret, Attempt.Left(UnknownFailure(new IllegalStateException("Missing inactiveTotpSecret"))))
          _ <- totp.checkCodeFatal(secret, code, time)
        } yield {
          before.copy(
            activeTotpSecret = Some(secret),
            inactiveTotpSecret = Some(ssg.createRandomSecret(totp.algorithm))
          )
        }

      case _ =>
        ???
    }
  }
}