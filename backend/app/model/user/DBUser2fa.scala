package model.user

import model._
import org.neo4j.driver.v1.Value
import utils.auth.totp._
import utils.auth.webauthn.WebAuthn
import scala.jdk.CollectionConverters._

// Originally we just had totpSecret as a field on DBUser but we need a lot more state to handle webauthn
// It's cleaner to store that all separately and allows us to "repair" write in the additional fields for existing users
case class DBUser2fa(
  // Filled in once the client has confirmed the code and we've checked it
  activeTotpSecret: Option[Secret],
  // Should be set even after registering to support moving to a new device
  inactiveTotpSecret: Option[Secret],
  // The webauthn user handle stored on the client shouldn't include PII or usernames
  // https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
  webAuthnUserHandle: Option[WebAuthn.UserHandle],
  // Each entry matches up with a webauthn 2fa method registered for the user (eg Yubikey)
  // Wrapper around the various serialisation formats defined by WebAuthn4j
  webAuthnAuthenticators: List[WebAuthn.WebAuthn4jAuthenticator],
  // Each operation (registration, verification) requires a challenge to defend against replay attacks
  // This field should be replaced after each successful operation (or call to generate new 2fa credentials)
  // TODO MRB: we could store this in an encrypted session cookie if we wanted to avoid database writes?
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
