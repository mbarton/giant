package utils.auth

import model.frontend.user.{TfaChallengeResponse, TfaRegistration, TotpCodeChallengeResponse, TotpCodeRegistration, TotpGenesisRegistration}
import model.user.DBUser2fa
import utils.attempt.{Attempt, LoginFailure, MisconfiguredAccount, SecondFactorRequired, UnknownFailure}
import utils.auth.totp.{Base32Secret, SecureSecretGenerator, Totp}
import utils.{Epoch, Logging}

import scala.concurrent.ExecutionContext

object TwoFactorAuth {
  case class CheckParams(username: String, tfa: DBUser2fa, challengeResponse: Option[TfaChallengeResponse], time: Epoch)
  type Check = CheckParams => Attempt[Unit]

  val NoCheck: Check = (_: CheckParams) => Attempt.Right(())
}

class TwoFactorAuth(require2fa: Boolean, totp: Totp, ssg: SecureSecretGenerator)(implicit ec: ExecutionContext) extends Logging {
  import TwoFactorAuth._

  def check2fa: Check = {
    case CheckParams(_, user2fa, _, _) if require2fa && !user2fa.hasMethodRegistered =>
      Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

    case CheckParams(_, user2fa, None, _) if require2fa || user2fa.hasMethodRegistered =>
      Attempt.Left(SecondFactorRequired("2FA code required"))

    case CheckParams(_, _, None, _) if !require2fa =>
      Attempt.Right(())

    case CheckParams(_, user2fa, Some(TotpCodeChallengeResponse(_)), _) if user2fa.activeTotpSecret.isEmpty =>
      Attempt.Left(LoginFailure("User not enrolled for TOTP"))

    case CheckParams(_, user2fa, Some(TotpCodeChallengeResponse(code)), time) if user2fa.activeTotpSecret.nonEmpty =>
      totp.checkCodeFatal(user2fa.activeTotpSecret.get, code, time)

    case CheckParams(username, user2fa, challengeResponse, _) =>
      logger.warn(s"${username} failed 2fa. registered: require2fa: ${require2fa}. activeTotpSecret: ${user2fa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
      Attempt.Left(SecondFactorRequired("Could not validate 2FA"))
  }

  def checkCanRegister: Check = {
    case CheckParams(_, user2fa, None, _) if user2fa.hasMethodRegistered =>
      Attempt.Left(SecondFactorRequired("2FA code required"))

    case CheckParams(_, user2fa, Some(TotpCodeChallengeResponse(_)), _) if user2fa.inactiveTotpSecret.isEmpty =>
      Attempt.Left(MisconfiguredAccount("Missing inactive TOTP secret"))

    case CheckParams(_, user2fa, Some(TotpCodeChallengeResponse(code)), time) if user2fa.activeTotpSecret.nonEmpty =>
      totp.checkCodeFatal(user2fa.activeTotpSecret.get, code, time)

    case CheckParams(_, user2fa, None, _) if !user2fa.hasMethodRegistered =>
      Attempt.Right(())

    case CheckParams(username, user2fa, challengeResponse, _) =>
      logger.warn(s"${username} failed check to register 2fa. require2fa: ${require2fa}. activeTotpSecret: ${user2fa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
      Attempt.Left(SecondFactorRequired("Could not validate 2FA"))
  }

  def checkRegistration(user2fa: DBUser2fa, registration: Option[TfaRegistration], time: Epoch): Attempt[DBUser2fa] = registration match {
    case None if !require2fa =>
      Attempt.Right(user2fa)

    case Some(TotpCodeRegistration(code)) => for {
      secret <- Attempt.fromOption(user2fa.inactiveTotpSecret, Attempt.Left(UnknownFailure(new IllegalStateException("Missing inactiveTotpSecret"))))
      _ <- totp.checkCodeFatal(secret, code, time)
    } yield {
      user2fa.copy(
        activeTotpSecret = Some(secret),
        inactiveTotpSecret = Some(ssg.createRandomSecret(totp.algorithm))
      )
    }

    case _ =>
      ???
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
