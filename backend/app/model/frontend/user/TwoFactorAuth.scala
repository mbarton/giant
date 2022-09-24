package model.frontend.user

import play.api.libs.json.{Format, JsError, JsResult, JsValue, Json, Reads, Writes}

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

object TfaRegistration {
  implicit val format: Format[TfaRegistration] = new Format[TfaRegistration] {
    override def reads(json: JsValue): JsResult[TfaRegistration] = {
      (json \ "type").validate[String].flatMap {
        case "totp" =>
          (json \ "code").validate[String].map(TotpCodeRegistration)

        case other => JsError(s"Unknown TfaChallengeResponse type ${other}")
      }
    }

    override def writes(r: TfaRegistration): JsValue = r match {
      case TotpCodeRegistration(code) => Json.obj(
        "type" -> "totp",
        "code" -> code
      )

      case other =>
        throw new IllegalArgumentException(s"Unknown TfaChallengeResponse type ${other.getClass}")
    }
  }
}

/**
 * What 2fa methods can be used. Sent to the client before performing 2fa
 */
case class TfaChallengeParameters(totp: Boolean, webAuthnCredentialIds: List[String], webAuthnChallenge: String)
object TfaChallengeParameters {
  implicit val format: Format[TfaChallengeParameters] = Json.format
}

sealed trait TfaChallengeResponse

case class TotpCodeChallengeResponse(code: String) extends TfaChallengeResponse

case class WebAuthnChallengeResponse() extends TfaChallengeResponse

object TfaChallengeResponse {
  implicit val format: Format[TfaChallengeResponse] = new Format[TfaChallengeResponse] {
    override def reads(json: JsValue): JsResult[TfaChallengeResponse] = {
      (json \ "type").validate[String].flatMap {
        case "totp" =>
          (json \ "code").validate[String].map(TotpCodeChallengeResponse)

        case other => JsError(s"Unknown TfaChallengeResponse type ${other}")
      }
    }

    override def writes(r: TfaChallengeResponse): JsValue = r match {
      case TotpCodeChallengeResponse(code) => Json.obj(
        "type" -> "totp",
        "code" -> "code"
      )

      case other =>
        throw new IllegalArgumentException(s"Unknown TfaChallengeResponse type ${other.getClass}")
    }
  }
}