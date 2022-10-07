package model.user

import model._
import org.neo4j.driver.v1.Value
import utils.auth.totp._
import utils.auth.webauthn.WebAuthn
import scala.collection.JavaConverters._

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

  def fromNeo4jValue(user: Value): DBUser2fa = DBUser2fa(
    activeTotpSecret = user.get("totpSecret").optionally(v => Base32Secret(v.asString)),
    inactiveTotpSecret = user.get("inactiveTotpSecret").optionally(v => Base32Secret(v.asString)),
    webAuthnUserHandle = user.get("webAuthnUserHandle").optionally(v => WebAuthn.UserHandle.decode(v.asString())),
    webAuthnAuthenticators = user.get("webAuthnAuthenticators").optionally(l =>
      l.asList((v: Value) => WebAuthn.WebAuthn4jAuthenticator.decode(v.asString())).asScala.toList).getOrElse(List.empty),
    webAuthnChallenge = user.get("webAuthnChallenge").optionally(v => WebAuthn.Challenge.decode(v.asString())),
  )
}
