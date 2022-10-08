package utils.auth.providers

import model.frontend.user._
import model.user._
import play.api.libs.json.{JsBoolean, JsNumber, JsString, JsValue, Json}
import play.api.mvc.{AnyContent, Request}
import services.DatabaseAuthConfig
import services.users.UserManagement
import utils.Epoch
import utils.attempt._
import utils.auth.totp.{Secret, SecureSecretGenerator, Totp}
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
    "minPasswordLength" -> JsNumber(config.minPasswordLength),
    "totpIssuer" -> JsString(config.totpIssuer)
  )

  override def genesisUserConfig(): Attempt[Map[String, JsValue]] = {
    val tfa = DBUser2fa.initial(ssg, totp)

    users.setGenesisRegistration2fa(tfa).map { _ =>
      Map(
        "totpSecret" -> JsString(tfa.inactiveTotpSecret.get.toBase32),
        "webAuthnChallenge" -> JsString(tfa.webAuthnChallenge.get.encode()),
        "webAuthnUserHandle" -> JsString(tfa.webAuthnUserHandle.get.encode())
      )
    }
  }

  override def authenticate(request: Request[AnyContent], time: Epoch): Attempt[PartialUser] =
    authenticateUser(request, time, RequireRegistered, tfa.check2fa).map(_.toPartial)

  override def genesisUser(request: JsValue, time: Epoch): Attempt[PartialUser] = {
    for {
      userData <- request.validate[NewGenesisUser].toAttempt
      encryptedPassword <- passwordHashing.hash(userData.password)
      _ <- passwordValidator.validate(userData.password)
      genesisTfa <- users.getGenesisRegistration2fa()
      userTfa <- tfa.checkRegistration(userData.username, genesisTfa, userData.tfa, time)
      // We will immediately register after creating
      user = DBUser(userData.username, None, None, invalidationTime = None, registered = false, userTfa)
      _ <- users.createUser(user, UserPermissions.bigBoss)
      registered <- users.registerUser(userData.username, userData.displayName, Some(encryptedPassword), Some(userTfa))
    } yield registered.toPartial
  }

  override def createUser(username: String, request: JsValue): Attempt[PartialUser] = {
    for {
      wholeUser <- request.validate[NewUser].toAttempt
      _ <- if (username == wholeUser.username) Attempt.Right(()) else Attempt.Left(ClientFailure("Username in URL didn't match that in payload."))
      _ <- passwordValidator.validate(wholeUser.password)
      hash <- passwordHashing.hash(wholeUser.password)
      user <- users.createUser(
          DBUser(wholeUser.username, Some("New User"), Some(hash), invalidationTime = None, registered = false, DBUser2fa.initial(ssg, totp)),
        UserPermissions.default
      )
    } yield user.toPartial
  }

  override def registerUser(request: JsValue, time: Epoch): Attempt[Unit] = {
    for {
      userData <- request.validate[UserRegistration].toAttempt
      user <- passwordHashing.verifyUser(users.getUser(userData.username), userData.previousPassword, RequireNotRegistered)
      _ <- passwordValidator.validate(userData.newPassword)
      newHash <- passwordHashing.hash(userData.newPassword)
      tfa <- tfa.checkRegistration(user.username, user.tfa, userData.tfa, time)
      _ <- users.registerUser(userData.username, userData.displayName, Some(newHash), Some(tfa))
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

  override def get2faRegistrationParameters(request: Request[AnyContent], time: Epoch): Attempt[TfaRegistrationParameters] = for {
    user <- authenticateUser(request, time, AllowUnregistered, tfa.checkCanRegister)
    username = user.username

    inactiveTotpSecret = user.tfa.inactiveTotpSecret.getOrElse(ssg.createRandomSecret(totp.algorithm))
    webAuthnUserHandle = user.tfa.webAuthnUserHandle.getOrElse(WebAuthn.UserHandle.create(ssg))
    webAuthnChallenge = user.tfa.webAuthnChallenge.getOrElse(WebAuthn.Challenge.create(ssg))

    newTfa = user.tfa.copy(
      inactiveTotpSecret = Some(inactiveTotpSecret),
      webAuthnUserHandle = Some(webAuthnUserHandle),
      webAuthnChallenge = Some(webAuthnChallenge)
    )

    _ <- users.setUser2fa(username, newTfa)
  } yield {
    val totpSecret = inactiveTotpSecret

    TfaRegistrationParameters(
      totpSecret = totpSecret.toBase32,
      webAuthnUserHandle = webAuthnUserHandle.encode(),
      webAuthnChallenge = webAuthnChallenge.encode(),
    )
  }

  private def authenticateUser(request: Request[AnyContent], time: Epoch, check: RegistrationCheck, checkTfa: TwoFactorAuth.Check): Attempt[DBUser] = {
    for {
      formData <- request.body.asFormUrlEncoded.toAttempt(Attempt.Left(ClientFailure("No form data")))
      username <- formData.get("username").flatMap(_.headOption).toAttempt(Attempt.Left(ClientFailure("No username form parameter")))
      password <- formData.get("password").flatMap(_.headOption).toAttempt(Attempt.Left(ClientFailure("No password form parameter")))
      tfaChallengeResponse <- if(formData.contains("tfa")) {
        Json.parse(formData("tfa").head).validate[TfaChallengeResponse].toAttempt.map(Some(_))
      } else {
        Attempt.Right(None)
      }
      dbUser <- passwordHashing.verifyUser(users.getUser(username), password, check)
      _ <- checkTfa(dbUser, tfaChallengeResponse, time).recoverWith {
        case SecondFactorRequired(username, _) =>
          // The webauthn challenge is currently stored in the database
          buildAndSave2faConfiguration(username, dbUser.tfa).flatMap { tfaChallenge =>
            Attempt.Left(SecondFactorRequired(username, TfaChallengeParameters.toAuthenticateHeader(tfaChallenge)))
          }
      }
    } yield dbUser
  }

  private def buildAndSave2faConfiguration(username: String, existing2fa: DBUser2fa): Attempt[TfaChallengeParameters] = {
    if(config.require2FA && existing2fa.activeTotpSecret.isEmpty) {
      Attempt.Left(MisconfiguredAccount("2FA enrollment is required"))
    } else {
      val challenge = WebAuthn.Challenge.create(ssg)
      val new2fa = existing2fa.copy(webAuthnChallenge = Some(challenge))

      users.setUser2fa(username, new2fa).map { _ =>
        TfaChallengeParameters(
          totp = existing2fa.activeTotpSecret.nonEmpty,
          webAuthnCredentialIds = new2fa.webAuthnAuthenticators.map(_.id.encode()),
          webAuthnChallenge = challenge.encode()
        )
      }
    }
  }
}