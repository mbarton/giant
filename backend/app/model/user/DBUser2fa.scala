package model.user

import org.neo4j.driver.v1.Value
import org.neo4j.driver.v1.types.Node
import utils.attempt.{Attempt, Neo4JValueFailure}
import utils.auth.totp._
import model.RichValue

import scala.collection.JavaConverters._

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
  webAuthnUserHandle: Option[Vector[Byte]],
  webAuthnPublicKeys: List[WebAuthnPublicKey],
  // to support registering an additional public key
  webAuthnChallenge: Option[Vector[Byte]]
)

object DBUser2fa {
  val empty: DBUser2fa = DBUser2fa(None, None, None, List.empty, None)

  def initial(ssg: SecureSecretGenerator, totp: Totp): DBUser2fa = DBUser2fa(
    activeTotpSecret = None,
    inactiveTotpSecret = Some(ssg.createRandomSecret(totp.algorithm)),
    // It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user’s account
    // https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
    webAuthnUserHandle = Some(ssg.createRandomSecret(Algorithm.HmacSHA512).data),
    webAuthnPublicKeys = List.empty,
    // Challenges SHOULD therefore be at least 16 bytes long.
    // https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
    webAuthnChallenge = Some(ssg.createRandomSecret(Algorithm.HmacSHA256).data)
  )

  def fromNeo4jValue(user: Value, webAuthnPublicKeys: List[Value]): DBUser2fa = {
    DBUser2fa(
      activeTotpSecret = user.get("totpSecret").optionally(v => Base32Secret(v.asString)),
      inactiveTotpSecret = user.get("inactiveTotpSecret").optionally(v => Base32Secret(v.asString)),
      // TODO MRB: not really a secret, I'm just re-using the base32 helpers out of laziness
      webAuthnUserHandle = user.get("webAuthnUserHandle").optionally(v => Base32Secret(v.asString).data),
      webAuthnPublicKeys = webAuthnPublicKeys.flatMap(_.optionally(v =>
        WebAuthnPublicKey(Base32Secret(v.get("id").asString).data, Base32Secret(v.get("publicKeyCose").asString).data)
      )),
      webAuthnChallenge = user.get("webAuthnChallenge").optionally(v => Base32Secret(v.asString).data)
    )
  }
}
