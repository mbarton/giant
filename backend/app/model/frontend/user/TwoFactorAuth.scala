package model.frontend.user

import play.api.libs.json._

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
 * Sent to the server when registering a WebAuthn public key (eg Yubikey)
 * All fields are base64url encoded
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
 * What 2fa methods can be used. Sent to the client in the WWW-Authenticate header to ask for 2fa to be performed
 */
case class TfaChallengeParameters(totp: Boolean, webAuthnCredentialIds: List[String], webAuthnChallenge: String)
object TfaChallengeParameters {
  def toAuthenticateHeader(params: TfaChallengeParameters): String = {
    List(
      // Retain the generic name for compatibility with older versions of Giant CLI
      if(params.totp) { Some("Pfi2fa") } else { None },
      if(params.webAuthnCredentialIds.nonEmpty) {
        Some(s"PfiWebAuthn challenge=${params.webAuthnChallenge} ${params.webAuthnCredentialIds.zipWithIndex.map {
          case (id, ix) => s"credential$ix=$id"
        }.mkString(" ")}")
      } else {
        None
      }
    ).flatten.mkString(", ")
  }
}

/**
 * Sent from the client to the server in response to a 401 with a challenge in the WWW-Authenticate header
 */
sealed trait TfaChallengeResponse

case class TotpCodeChallengeResponse(code: String) extends TfaChallengeResponse

case class WebAuthnChallengeResponse(id: String, clientDataJson: String, authenticatorData: String, signature: String, userHandle: Option[String]) extends TfaChallengeResponse

object TfaChallengeResponse {
  private implicit val totpCodeChallengeResponseFormat: Format[TotpCodeChallengeResponse] = Json.format[TotpCodeChallengeResponse]
  private implicit val webAuthnChallengeResponseFormat: Format[WebAuthnChallengeResponse] = Json.format[WebAuthnChallengeResponse]

  // TODO MRB: read these as separate fields in the form submission rather than crowbarring it in to JSON
  implicit val format: Format[TfaChallengeResponse] = new Format[TfaChallengeResponse] {
    override def reads(json: JsValue): JsResult[TfaChallengeResponse] = {
      (json \ "type").validate[String].flatMap {
        case "totp" => json.validate[TotpCodeChallengeResponse]
        case "webauthn" => json.validate[WebAuthnChallengeResponse]
        case other => JsError(s"Unknown TfaChallengeResponse type ${other}")
      }
    }

    override def writes(r: TfaChallengeResponse): JsValue = r match {
      case r: TotpCodeChallengeResponse => totpCodeChallengeResponseFormat.writes(r)
      case r: WebAuthnChallengeResponse => webAuthnChallengeResponseFormat.writes(r)
      case other =>
        throw new IllegalArgumentException(s"Unknown TfaChallengeResponse type ${other.getClass}")
    }
  }
}