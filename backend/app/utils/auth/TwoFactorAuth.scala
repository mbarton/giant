package utils.auth

import model.frontend.user.{TfaChallengeResponse, TotpCodeChallengeResponse, WebAuthnChallengeResponse}
import model.user.DBUser2fa
import utils.Epoch
import utils.attempt.{Attempt, ClientFailure, SecondFactorRequired}
import utils.auth.totp.Totp

import scala.concurrent.ExecutionContext

class TwoFactorAuth(totp: Totp) {
  def check2fa(userTfa: DBUser2fa, challengeResponse: TfaChallengeResponse, time: Epoch)(implicit ec: ExecutionContext): Attempt[Unit] = challengeResponse match {
    case TotpCodeChallengeResponse(_) if userTfa.activeTotpSecret.isEmpty =>
      Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

    case TotpCodeChallengeResponse(code) =>
      totp.checkCodeFatal(userTfa.activeTotpSecret.get, code, time, ClientFailure("2FA code wasn't valid, check the time on your device")).map(_ => ())

    case WebAuthnChallengeResponse() =>
      ???
  }
}
