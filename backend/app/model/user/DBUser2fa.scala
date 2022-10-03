package model.user

import com.webauthn4j.data.AuthenticatorTransport
import play.api.libs.json.{Format, JsResult, JsValue, Json}
import utils.auth.totp._
import utils.auth.webauthn.WebAuthn

// Originally we just had totpSecret as a field on DBUser but we need a lot more state to handle webauthn
// It's cleaner to store that all separately and allows us to "repair" write in the additional fields for existing users
case class DBUser2fa(
  // filled in once the client has confirmed the code and we've checked it
  activeTotpSecret: Option[Secret],
  // to support moving to a new device
  inactiveTotpSecret: Option[Secret],
  // the webauthn user handle stored on the client shouldn't include PII or usernames
  // https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
  webAuthnUserHandle: Option[WebAuthn.UserHandle],
  webAuthnAuthenticators: List[WebAuthn.WebAuthn4jAuthenticator],
  // to support registering an additional public key
  webAuthnChallenge: Option[WebAuthn.Challenge]
) {
  def hasMethodRegistered: Boolean = activeTotpSecret.nonEmpty || webAuthnAuthenticators.nonEmpty
}

object DBUser2fa {
  val empty: DBUser2fa = DBUser2fa(None, None, None, List.empty, None)

  def initial(ssg: SecureSecretGenerator, totp: Totp): DBUser2fa = DBUser2fa(
    activeTotpSecret = None,
    inactiveTotpSecret = Some(ssg.createRandomSecret(totp.algorithm)),
    webAuthnUserHandle = Some(WebAuthn.UserHandle.create(ssg)),
    webAuthnAuthenticators = List.empty,
    webAuthnChallenge = Some(WebAuthn.Challenge.create(ssg))
  )
}
