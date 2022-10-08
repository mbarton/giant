package model.frontend.user

import play.api.libs.json._
import utils.auth.webauthn.WebAuthn

/**
 * Sent to the client before registering a new 2fa method
 */
case class TfaRegistrationParameters(totpSecret: String, webAuthnUserHandle: String, webAuthnChallenge: String)
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
 * All fields are base64 encoded
 */
case class WebAuthnPublicKeyRegistration(id: String, clientDataJson: String, attestationObject: String) extends TfaRegistration

object TfaRegistration {
  private implicit val totpCodeRegistrationFormat: Format[TotpCodeRegistration] = Json.format[TotpCodeRegistration]
  private implicit val webAuthnPublicKeyRegistration: Format[WebAuthnPublicKeyRegistration] = Json.format[WebAuthnPublicKeyRegistration]

  implicit val format: Format[TfaRegistration] = new Format[TfaRegistration] {
    override def reads(json: JsValue): JsResult[TfaRegistration] = {
      (json \ "type").validate[String].flatMap {
        case "totp" =>
          json.validate[TotpCodeRegistration]

        case "webauthn" =>
          json.validate[WebAuthnPublicKeyRegistration]

        case other => JsError(s"Unknown TfaChallengeResponse type ${other}")
      }
    }

    override def writes(r: TfaRegistration): JsValue = r match {
      case r: TotpCodeRegistration =>
        Json.toJson(r).as[JsObject] ++ Json.obj("type" -> "totp")

      case r: WebAuthnPublicKeyRegistration =>
        Json.toJson(r)

      case other =>
        throw new IllegalArgumentException(s"Unknown TfaChallengeResponse type ${other.getClass}")
    }
  }
}

/**
 * What 2fa methods can be used. Sent to the client before performing 2fa
 */
case class TfaChallengeParameters(totp: Boolean, webAuthnCredentialIds: List[WebAuthn.CredentialId], webAuthnChallenge: WebAuthn.Challenge)
object TfaChallengeParameters {
  def toAuthenticateHeader(params: TfaChallengeParameters): String = {
    List(
      // Retain the generic name for compatibility with older versions of Giant CLI
      if(params.totp) { Some("Pfi2fa") } else { None },
      if(params.webAuthnCredentialIds.nonEmpty) {
        Some(s"PfiWebAuthn challenge=${params.webAuthnChallenge.encode()} ${params.webAuthnCredentialIds.zipWithIndex.map {
          case (id, ix) => s"credential$ix=${id.encode()}"
        }.mkString(" ")}")
      } else {
        None
      }
    ).flatten.mkString(", ")
  }
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