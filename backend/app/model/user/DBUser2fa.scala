package model.user

import model.RichValue
import org.neo4j.driver.v1.Value
import utils.auth.totp._
import utils.auth.webauthn.WebAuthn

case class WebAuthnPublicKey(id: Vector[Byte], publicKeyCose: Vector[Byte])

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
  webAuthnPublicKeys: List[WebAuthnPublicKey],
  // to support registering an additional public key
  webAuthnChallenge: Option[WebAuthn.Challenge]
) {
  def hasMethodRegistered: Boolean = activeTotpSecret.nonEmpty || webAuthnPublicKeys.nonEmpty
}

object DBUser2fa {
  val empty: DBUser2fa = DBUser2fa(None, None, None, List.empty, None)

  def initial(ssg: SecureSecretGenerator, totp: Totp): DBUser2fa = DBUser2fa(
    activeTotpSecret = None,
    inactiveTotpSecret = Some(ssg.createRandomSecret(totp.algorithm)),
    webAuthnUserHandle = Some(WebAuthn.UserHandle.create(ssg)),
    webAuthnPublicKeys = List.empty,
    webAuthnChallenge = Some(WebAuthn.Challenge.create(ssg))
  )

  def fromNeo4jValue(user: Value, webAuthnPublicKeys: List[Value]): DBUser2fa = {
    DBUser2fa(
      activeTotpSecret = user.get("totpSecret").optionally(v => Base32Secret(v.asString)),
      inactiveTotpSecret = user.get("inactiveTotpSecret").optionally(v => Base32Secret(v.asString)),
      webAuthnUserHandle = user.get("webAuthnUserHandle").optionally(v => WebAuthn.UserHandle(WebAuthn.fromBase64(v.asString()))),
      webAuthnPublicKeys = webAuthnPublicKeys.flatMap(_.optionally(v =>
        WebAuthnPublicKey(
          WebAuthn.fromBase64(v.get("id").asString()),
          WebAuthn.fromBase64(v.get("publicKeyCose").asString())
        )
      )),
      webAuthnChallenge = user.get("webAuthnChallenge").optionally(v => WebAuthn.Challenge(WebAuthn.fromBase64(v.asString()))),
    )
  }
}
