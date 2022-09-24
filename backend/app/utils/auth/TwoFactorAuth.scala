package utils.auth

import model.frontend.user.{TfaChallengeResponse, TotpCodeChallengeResponse}
import model.user.{DBUser, DBUser2fa}
import services.users.UserManagement
import utils.attempt.{Attempt, LoginFailure, MisconfiguredAccount, SecondFactorRequired}
import utils.auth.totp.Totp
import utils.{Epoch, Logging}

import scala.concurrent.ExecutionContext

object TwoFactorAuth {
  type Check = (String, Option[TfaChallengeResponse], Epoch) => Attempt[Unit]

  val NoCheck: Check = (_: String, _: Option[TfaChallengeResponse], _: Epoch) => Attempt.Right(())
}

class TwoFactorAuth(require2fa: Boolean, totp: Totp, users: UserManagement)(implicit ec: ExecutionContext) extends Logging {
  def check2fa(username: String, challengeResponse: Option[TfaChallengeResponse], time: Epoch): Attempt[Unit] = {
    getUserData(username, challengeResponse).flatMap {
      case (_, user2fa, _) if require2fa && !user2fa.hasMethodRegistered =>
        Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

      case (_, user2fa, None) if require2fa || user2fa.hasMethodRegistered =>
        Attempt.Left(SecondFactorRequired("2FA code required"))

      case (_, _, None) if !require2fa =>
        Attempt.Right(())

      case (_, user2fa, Some(TotpCodeChallengeResponse(_))) if user2fa.activeTotpSecret.isEmpty =>
        Attempt.Left(LoginFailure("User not enrolled for TOTP"))

      case (_, user2fa, Some(TotpCodeChallengeResponse(code))) if user2fa.activeTotpSecret.nonEmpty =>
        totp.checkCodeFatal(user2fa.activeTotpSecret.get, code, time)

      case (user, user2fa, challengeResponse) =>
        logger.warn(s"${username} failed 2fa. registered: ${user.registered} require2fa: ${require2fa}. activeTotpSecret: ${user2fa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
        Attempt.Left(SecondFactorRequired("Could not validate 2FA"))
    }
  }

  def checkCanRegister(username: String, challengeResponse: Option[TfaChallengeResponse], time: Epoch): Attempt[Unit] = {
    getUserData(username, challengeResponse).flatMap {
      case (_, user2fa, None) if user2fa.hasMethodRegistered =>
        Attempt.Left(SecondFactorRequired("2FA code required"))

      case (_, user2fa, Some(TotpCodeChallengeResponse(_))) if user2fa.inactiveTotpSecret.isEmpty =>
        Attempt.Left(MisconfiguredAccount("Missing inactive TOTP secret"))

      case (_, user2fa, Some(TotpCodeChallengeResponse(code))) =>
        totp.checkCodeFatal(user2fa.activeTotpSecret.get, code, time)

      case (user, user2fa, None) if !user.registered && !user2fa.hasMethodRegistered =>
        Attempt.Right(())

      case (user, user2fa, challengeResponse) =>
        logger.warn(s"${username} failed check to register 2fa. registered: ${user.registered} require2fa: ${require2fa}. activeTotpSecret: ${user2fa.activeTotpSecret.nonEmpty}. challengeResponse: ${challengeResponse.map(_.getClass.getName).getOrElse("None")}")
        Attempt.Left(SecondFactorRequired("Could not validate 2FA"))
    }
  }

  private def getUserData(username: String, challengeResponse: Option[TfaChallengeResponse]): Attempt[(DBUser, DBUser2fa, Option[TfaChallengeResponse])] = for {
    user <- users.getUser(username)
    tfa <- users.getUser2fa(username)
  } yield (user, tfa, challengeResponse)
}
