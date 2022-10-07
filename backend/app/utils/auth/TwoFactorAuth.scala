package utils.auth

import model.frontend.user._
import model.user.{DBUser, DBUser2fa}
import utils.attempt.{Attempt, LoginFailure, MisconfiguredAccount, SecondFactorRequired, SupportedSecondFactor, UnknownFailure}
import utils.auth.totp.{SecureSecretGenerator, Totp}
import utils.auth.webauthn.WebAuthn
import utils.{Epoch, Logging}

import scala.concurrent.ExecutionContext

object TwoFactorAuth {
  type Check = (DBUser, Option[TfaChallengeResponse], Epoch) => Attempt[Unit]

  val NoCheck: Check = (_: DBUser, _: Option[TfaChallengeResponse], _: Epoch) => Attempt.Right(())
}

class TwoFactorAuth(require2fa: Boolean, totp: Totp, ssg: SecureSecretGenerator)(implicit ec: ExecutionContext) extends Logging {
  import TwoFactorAuth._

  def check2fa: Check = {
    case (user, _, _) if require2fa && !user.tfa.hasMethodRegistered =>
      Attempt.Left(LoginFailure("2FA enrollment is required"))

    case (user, None, _) if require2fa || user.tfa.hasMethodRegistered =>
      Attempt.Left(buildSecondFactorRequiredFailure(user.tfa))

    case (_, None, _) if !require2fa =>
      Attempt.Right(())

    case (user, Some(TotpCodeChallengeResponse(_)), _) if user.tfa.activeTotpSecret.isEmpty =>
      Attempt.Left(LoginFailure("User not enrolled for TOTP"))

    case (user, Some(TotpCodeChallengeResponse(code)), time) if user.tfa.activeTotpSecret.nonEmpty =>
      totp.checkCodeFatal(user.tfa.activeTotpSecret.get, code, time)

    case (user, challengeResponse, _) =>
      logger.warn(s"${user.username} failed 2fa. registered: require2fa: ${require2fa}. activeTotpSecret: ${user.tfa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
      Attempt.Left(LoginFailure("Could not validate 2FA"))
  }

  def checkCanRegister: Check = {
    case (user, None, _) if user.tfa.hasMethodRegistered =>
      Attempt.Left(buildSecondFactorRequiredFailure(user.tfa))

    case (user, Some(TotpCodeChallengeResponse(_)), _) if user.tfa.inactiveTotpSecret.isEmpty =>
      Attempt.Left(MisconfiguredAccount("Missing inactive TOTP secret"))

    case (user, Some(TotpCodeChallengeResponse(code)), time) if user.tfa.activeTotpSecret.nonEmpty =>
      totp.checkCodeFatal(user.tfa.activeTotpSecret.get, code, time)

    case (user, None, _) if !user.tfa.hasMethodRegistered =>
      Attempt.Right(())

    case (user, challengeResponse, _) =>
      logger.warn(s"${user.username} failed check to register 2fa. require2fa: ${require2fa}. activeTotpSecret: ${user.tfa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
      Attempt.Left(LoginFailure("Could not validate 2FA"))
  }

  def checkRegistration(username: String, user2fa: DBUser2fa, registration: Option[TfaRegistration], time: Epoch): Attempt[DBUser2fa] = registration match {
    case None if !require2fa =>
      Attempt.Right(user2fa)

    case None =>
      Attempt.Left(LoginFailure("2FA is required"))

    case Some(TotpCodeRegistration(code)) => for {
      secret <- Attempt.fromOption(user2fa.inactiveTotpSecret, Attempt.Left(UnknownFailure(new IllegalStateException("Missing inactiveTotpSecret"))))
      _ <- totp.checkCodeFatal(secret, code, time)
    } yield {
      user2fa.copy(
        activeTotpSecret = Some(secret),
        inactiveTotpSecret = Some(ssg.createRandomSecret(totp.algorithm))
      )
    }

    case Some(registration: WebAuthnPublicKeyRegistration) =>
      WebAuthn.verifyRegistration(username, user2fa, registration, ssg)
  }

  def buildSecondFactorRequiredFailure(tfa: DBUser2fa): SecondFactorRequired = {
    val totpMethod = if(tfa.activeTotpSecret.nonEmpty) { List(SupportedSecondFactor.Totp) } else { List.empty }
    val webAuthnMethods = tfa.webAuthnAuthenticators.map { auth => SupportedSecondFactor.Webauthn(auth.id.encodeUrl()) }

    SecondFactorRequired(
      "2FA required",
      totpMethod ++ webAuthnMethods
    )
  }
}
