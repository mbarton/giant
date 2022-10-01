package model.user

import model.RichValue
import org.neo4j.driver.v1.Value
import play.api.libs.json.{Format, JsResult, JsValue, Json}
import utils.auth.totp._
import utils.auth.webauthn.WebAuthn

import scala.collection.JavaConverters._

case class WebAuthnPublicKey(id: Vector[Byte], publicKeyCose: Vector[Byte])
object WebAuthnPublicKey {
  implicit val format: Format[WebAuthnPublicKey] = new Format[WebAuthnPublicKey] {
    override def reads(json: JsValue): JsResult[WebAuthnPublicKey] = for {
      id <- (json \ "id").validate[String]
      publicKeyCose <- (json \ "publicKeyCose").validate[String]
    } yield WebAuthnPublicKey(WebAuthn.fromBase64(id), WebAuthn.fromBase64(publicKeyCose))

    override def writes(o: WebAuthnPublicKey): JsValue = Json.obj(
      "id" -> WebAuthn.toBase64(o.id),
      "publicKeyCose" -> WebAuthn.toBase64(o.publicKeyCose)
    )
  }
}

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
}
