package utils.auth

import model.frontend.user.{TfaChallengeResponse, TfaRegistration, TotpCodeChallengeResponse, TotpCodeRegistration, TotpGenesisRegistration, WebAuthnPublicKeyRegistration}
import model.user.{DBUser, DBUser2fa}
import utils.attempt.{Attempt, LoginFailure, MisconfiguredAccount, SecondFactorRequired, UnknownFailure}
import utils.auth.totp.{Base32Secret, SecureSecretGenerator, Totp}
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
      Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

    case (user, None, _) if require2fa || user.tfa.hasMethodRegistered =>
      Attempt.Left(SecondFactorRequired("2FA code required"))

    case (_, None, _) if !require2fa =>
      Attempt.Right(())

    case (user, Some(TotpCodeChallengeResponse(_)), _) if user.tfa.activeTotpSecret.isEmpty =>
      Attempt.Left(LoginFailure("User not enrolled for TOTP"))

    case (user, Some(TotpCodeChallengeResponse(code)), time) if user.tfa.activeTotpSecret.nonEmpty =>
      totp.checkCodeFatal(user.tfa.activeTotpSecret.get, code, time)

    case (user, challengeResponse, _) =>
      logger.warn(s"${user.username} failed 2fa. registered: require2fa: ${require2fa}. activeTotpSecret: ${user.tfa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
      Attempt.Left(SecondFactorRequired("Could not validate 2FA"))
  }

  def checkCanRegister: Check = {
    case (user, None, _) if user.tfa.hasMethodRegistered =>
      Attempt.Left(SecondFactorRequired("2FA code required"))

    case (user, Some(TotpCodeChallengeResponse(_)), _) if user.tfa.inactiveTotpSecret.isEmpty =>
      Attempt.Left(MisconfiguredAccount("Missing inactive TOTP secret"))

    case (user, Some(TotpCodeChallengeResponse(code)), time) if user.tfa.activeTotpSecret.nonEmpty =>
      totp.checkCodeFatal(user.tfa.activeTotpSecret.get, code, time)

    case (user, None, _) if !user.tfa.hasMethodRegistered =>
      Attempt.Right(())

    case (user, challengeResponse, _) =>
      logger.warn(s"${user.username} failed check to register 2fa. require2fa: ${require2fa}. activeTotpSecret: ${user.tfa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
      Attempt.Left(SecondFactorRequired("Could not validate 2FA"))
  }

  def checkRegistration(username: String, user2fa: DBUser2fa, registration: Option[TfaRegistration], time: Epoch): Attempt[DBUser2fa] = registration match {
    case None if !require2fa =>
      Attempt.Right(user2fa)

    case None =>
      Attempt.Left(SecondFactorRequired("2FA is required"))

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

  def checkGenesisRegistration(registration: Option[TfaRegistration], time: Epoch): Attempt[DBUser2fa] = registration match {
    case None if !require2fa =>
      Attempt.Right(DBUser2fa.initial(ssg, totp))

    case Some(TotpGenesisRegistration(secretString, code)) =>
      val secret = Base32Secret(secretString)

      totp.checkCodeFatal(secret, code, time).map { _ =>
        DBUser2fa.initial(ssg, totp).copy(
          activeTotpSecret = Some(secret)
        )
      }
  }
}
