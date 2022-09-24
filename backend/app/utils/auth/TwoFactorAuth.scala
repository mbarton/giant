package utils.auth

import model.frontend.user.{TfaChallengeResponse, TotpCodeChallengeResponse, WebAuthnChallengeResponse}
import model.user.DBUser2fa
import services.users.UserManagement
import utils.Epoch
import utils.attempt.{Attempt, ClientFailure, LoginFailure, MisconfiguredAccount, SecondFactorRequired, UnsupportedOperationFailure}
import utils.auth.totp.Totp

import scala.concurrent.ExecutionContext

class TwoFactorAuth(require2fa: Boolean, totp: Totp, users: UserManagement)(implicit ec: ExecutionContext) {
  def check2fa(username: String, challengeResponse: Option[TfaChallengeResponse], time: Epoch, registrationCheck: RegistrationCheck): Attempt[Unit] = {
    users.getUser(username).map { user =>
      (registrationCheck, user.registered, require2fa, challengeResponse) match {
        case (RequireRegistered, true, true, Some(r)) => check2faChallengeResponse(username, r, time)
        case (RequireRegistered, true, true, None) => Attempt.Left(SecondFactorRequired("2FA code required"))

        case (RequireRegistered, true, false, Some(r)) => check2faChallengeResponse(username, r, time)
        case (RequireRegistered, true, false, None) => Attempt.Right(())

        case (RequireRegistered, false, _, _) => Attempt.Left(LoginFailure("User requires registration"))
        case (RequireNotRegistered, true, _, _) => Attempt.Left(LoginFailure("User already registered"))

        case (RequireNotRegistered, false, true, Some(r)) => check2faChallengeResponse(username, r, time)
        case (RequireNotRegistered, false, true, None) => Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

        case (RequireNotRegistered, false, false, Some(r)) => check2faChallengeResponse(username, r, time)
        case (RequireNotRegistered, false, false, None) => Attempt.Right(())

        case (AllowUnregistered, _, true, Some(r)) => check2faChallengeResponse(username, r, time)
        case (AllowUnregistered, _, true, None) => Attempt.Left(SecondFactorRequired("2FA code required"))

        case (AllowUnregistered, _, false, Some(r)) => check2faChallengeResponse(username, r, time)
        case (AllowUnregistered, _, false, None) => Attempt.Right(())
      }
    }
  }

  private def check2faChallengeResponse(username: String, challengeResponse: TfaChallengeResponse, time: Epoch): Attempt[Unit] = {
    users.getUser2fa(username).map { user2fa =>
      challengeResponse match {
        case TotpCodeChallengeResponse(_) if user2fa.activeTotpSecret.isEmpty =>
          Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

        case TotpCodeChallengeResponse(code) =>
          totp.checkCodeFatal(user2fa.activeTotpSecret.get, code, time)

        case WebAuthnChallengeResponse() =>
          Attempt.Left(UnsupportedOperationFailure("Webauthn is not implemented yet!"))
      }
    }
  }
}
