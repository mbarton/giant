package model.frontend.user

import play.api.libs.json.{Json, Writes}

/**
 * Sent to the client before registering a new 2fa method
 */
case class TfaRegistrationParameters(totpSecret: String, totpUrl: String, webAuthnUserHandle: String, webAuthnChallenge: String)
object TfaRegistrationParameters {
  implicit val writes: Writes[TfaRegistrationParameters] = Json.writes[TfaRegistrationParameters]
}

sealed trait TfaRegistration

/**
 * Sent to the server when registering via TOTP (eg Google Authenticator)
 * Contains the code to ensure it works before starting to use it
 */
case class TotpCodeRegistration(code: String) extends TfaRegistration

/**
 * Sent to the server when registering a WebAuthn public key (eg Yubikey, iOS passkey)
 * See https://www.w3.org/TR/webauthn-2/#dictionary-client-data
 */
// TODO MRB: also store attestation documents?
case class WebAuthnClientData(id: String, challenge: String, origin: String) extends TfaRegistration

/**
 * What 2fa methods can be used. Sent to the client before performing 2fa
 */
case class TfaUserConfiguration(totp: Boolean, webAuthnCredentialIds: List[String], webAuthnChallenge: String)

sealed trait TfaChallengeResponse

case class TotpCodeChallengeResponse(code: String) extends TfaChallengeResponse

case class WebAuthnChallengeResponse() extends TfaChallengeResponse
