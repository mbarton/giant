package model.user

import model._
import model.frontend.user.PartialUser
import org.neo4j.driver.v1.Value
import play.api.libs.json.Json
import utils.auth.totp.Base32Secret
import utils.auth.webauthn.WebAuthn
import scala.collection.JavaConverters._

/* User model for representation in the database */
case class DBUser(username: String, displayName: Option[String], password: Option[BCryptPassword],
                  invalidationTime: Option[Long], registered: Boolean, tfa: DBUser2fa) {
  def toPartial = PartialUser(username, displayName.getOrElse(username))
}

object DBUser {
  // this deliberately has no Json Formats as this should never be sent to a client

  def fromNeo4jValue(user: Value): DBUser = {
    DBUser(
      user.get("username").asString,
      user.get("displayName").optionally(_.asString),
      user.get("password").optionally(v => BCryptPassword.apply(v.asString)),
      user.get("invalidationTime").optionally(_.asLong),
      user.get("registered").optionally(_.asBoolean).getOrElse(false),
      DBUser2fa(
        activeTotpSecret = user.get("totpSecret").optionally(v => Base32Secret(v.asString)),
        inactiveTotpSecret = user.get("inactiveTotpSecret").optionally(v => Base32Secret(v.asString)),
        webAuthnUserHandle = user.get("webAuthnUserHandle").optionally(v => WebAuthn.UserHandle(WebAuthn.fromBase64(v.asString()))),
        webAuthnPublicKeys = user.get("webAuthnPublicKeys").optionally(l =>
          l.asList((v: Value) => Json.parse(v.asString()).as[WebAuthnPublicKey]).asScala.toList).getOrElse(List.empty),
        webAuthnChallenge = user.get("webAuthnChallenge").optionally(v => WebAuthn.Challenge(WebAuthn.fromBase64(v.asString()))),
      )
    )
  }
}