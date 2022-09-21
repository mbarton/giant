package utils.auth

import model.frontend.user.{TfaChallengeResponse, TotpCodeChallengeResponse, WebAuthnChallengeResponse}
import model.user.DBUser2fa
import utils.Epoch
import utils.attempt.{Attempt, ClientFailure, SecondFactorRequired}
import utils.auth.totp.Totp

import scala.concurrent.ExecutionContext

class TwoFactorAuth(require2fa: Boolean, totp: Totp) {
  def check2fa(userTfa: DBUser2fa, challengeResponse: Option[TfaChallengeResponse], time: Epoch)(implicit ec: ExecutionContext): Attempt[Boolean] = challengeResponse match {
    case None if require2fa =>
      Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

    case Some(TotpCodeChallengeResponse(_)) if userTfa.activeTotpSecret.isEmpty =>
      Attempt.Left(SecondFactorRequired("2FA enrollment is required"))

    case Some(TotpCodeChallengeResponse(code)) =>
      totp.checkCodeFatal(userTfa.activeTotpSecret.get, code, time, ClientFailure("Sample 2FA code wasn't valid, check the time on your device"))

    case Some(WebAuthnChallengeResponse()) =>
      ???

    case None =>
      Attempt.Right(true)
  }
}
