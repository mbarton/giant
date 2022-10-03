package utils.auth.webauthn

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.authenticator.{Authenticator, AuthenticatorImpl}
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.exception.DataConversionException
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.{DefaultChallenge => WebAuthn4JChallenge}
import com.webauthn4j.data.extension.authenticator.{AuthenticationExtensionsAuthenticatorOutputs, RegistrationExtensionAuthenticatorOutput}
import com.webauthn4j.data.extension.client.{AuthenticationExtensionsClientOutputs, RegistrationExtensionClientOutput}
import com.webauthn4j.data.{AuthenticatorTransport, RegistrationParameters, RegistrationRequest}
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.validator.exception.ValidationException
import model.frontend.user.WebAuthnPublicKeyRegistration
import model.user.DBUser2fa
import play.api.libs.json.{Format, JsArray, JsNumber, JsResult, JsString, JsValue, Json}
import utils.Logging
import utils.attempt._
import utils.auth.totp.{Algorithm, SecureSecretGenerator}

import scala.collection.JavaConverters._
import java.util.Base64

object WebAuthn extends Logging {
  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()
  private val webAuthnObjectConverter = new ObjectConverter(new ObjectMapper(), new ObjectMapper(new CBORFactory()))
  private val attestedCredentialDataConverter = new AttestedCredentialDataConverter(webAuthnObjectConverter)

  // TODO MRB: how to determine these?
  val origin = "http://localhost:3000"
  val rpId = "localhost"

  // TODO MRB: what else should we support?
  val supportedAlg = -7 // ECDSA w/ SHA-256 https://www.iana.org/assignments/cose/cose.xhtml#algorithms

  // It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user’s account
  // https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
  case class UserHandle(data: Vector[Byte]) {
    def encode(): String = toBase64(data)
  }
  object UserHandle {
    def apply(data: Vector[Byte]): UserHandle = {
      assert(data.length == 64)
      new UserHandle(data)
    }

    def create(ssg: SecureSecretGenerator): UserHandle = {
      UserHandle(ssg.createRandomSecret(Algorithm.HmacSHA512).data)
    }

    def decode(input: String): UserHandle = UserHandle(fromBase64(input))
  }

  // Challenges SHOULD therefore be at least 16 bytes long.
  // https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
  case class Challenge(data: Vector[Byte]) {
    def encode(): String = toBase64(data)
  }

  object Challenge {
    def apply(data: Vector[Byte]): Challenge = {
      assert(data.length == 32)
      new Challenge(data)
    }

    def create(ssg: SecureSecretGenerator): Challenge = {
      Challenge(ssg.createRandomSecret(Algorithm.HmacSHA256).data)
    }

    def decode(input: String): Challenge = Challenge(fromBase64(input))
  }

  case class CredentialId(data: Vector[Byte]) {
    def encode(): String = toBase64(data)
  }

  object CredentialId {
    def decode(input: String): CredentialId = CredentialId(fromBase64(input))
  }

  // https://webauthn4j.github.io/webauthn4j/en/#representation-of-an-authenticator
  // TODO MRB: request attestation and store attestationStatement?
  case class WebAuthn4jAuthenticator(
      id: CredentialId,
      attestedCredentialData: AttestedCredentialData,
      transports: Set[AuthenticatorTransport],
      counter: Long,
      authenticatorExtensions: AuthenticationExtensionsAuthenticatorOutputs[RegistrationExtensionAuthenticatorOutput],
      clientExtensions: AuthenticationExtensionsClientOutputs[RegistrationExtensionClientOutput]
    ) {
    def instance(): Authenticator = new AuthenticatorImpl(attestedCredentialData, null, counter, transports.asJava, clientExtensions, authenticatorExtensions)

    def encode(): String = {
      Json.stringify(Json.toJson(this)(WebAuthn4jAuthenticator.format.writes))
    }
  }

  object WebAuthn4jAuthenticator {
    val format: Format[WebAuthn4jAuthenticator] = new Format[WebAuthn4jAuthenticator] {
      override def reads(json: JsValue): JsResult[WebAuthn4jAuthenticator] = for {
        id <- (json \ "id").validate[String].map(CredentialId.decode)
        attestedCredentialData <- (json \ "attestedCredentialData").validate[String].map { v => attestedCredentialDataConverter.convert(fromBase64(v).toArray) }
        transports <- (json \ "transports").validate[List[String]].map(_.map(AuthenticatorTransport.create)).map(_.toSet)
        counter <- (json \ "counter").validate[Long]
        authenticatorExtensions <- (json \ "authenticatorExtensions").validate[String].map { v =>
          webAuthnObjectConverter.getCborConverter.readValue[AuthenticationExtensionsAuthenticatorOutputs[_]](fromBase64(v).toArray, classOf[AuthenticationExtensionsAuthenticatorOutputs[_]])
        }
        clientExtensions <- (json \ "clientExtensions").validate[String].map { v =>
          webAuthnObjectConverter.getJsonConverter.readValue[AuthenticationExtensionsClientOutputs[_]](v, classOf[AuthenticationExtensionsClientOutputs[_]])
        }
      } yield {
        WebAuthn4jAuthenticator(
          id,
          attestedCredentialData,
          transports,
          counter,
          authenticatorExtensions.asInstanceOf[AuthenticationExtensionsAuthenticatorOutputs[RegistrationExtensionAuthenticatorOutput]],
          clientExtensions.asInstanceOf[AuthenticationExtensionsClientOutputs[RegistrationExtensionClientOutput]])
      }

      override def writes(o: WebAuthn4jAuthenticator): JsValue = {
        Json.obj(
          "id" -> JsString(o.id.encode()),
          "attestedCredentialData" -> JsString(toBase64(attestedCredentialDataConverter.convert(o.attestedCredentialData).toVector)),
          "transports" -> JsArray(o.transports.map { t => JsString(t.toString) }.toList),
          "counter" -> JsNumber(o.counter),
          "authenticatorExtensions" -> JsString(toBase64(webAuthnObjectConverter.getCborConverter.writeValueAsBytes(o.authenticatorExtensions).toVector)),
          "clientExtensions" -> JsString(webAuthnObjectConverter.getJsonConverter.writeValueAsString(o.authenticatorExtensions))
        )
      }
    }

    def decode(input: String): WebAuthn4jAuthenticator = {
      Json.parse(input).as[WebAuthn4jAuthenticator](format.reads)
    }
  }

  private def toBase64(data: Vector[Byte]): String = Base64.getEncoder.encodeToString(data.toArray)

  private def fromBase64(data: String): Vector[Byte] = Base64.getDecoder.decode(data).toVector

  def verifyRegistration(username: String, tfa: DBUser2fa, registration: WebAuthnPublicKeyRegistration, ssg: SecureSecretGenerator): Attempt[DBUser2fa] = {
    val challenge = new WebAuthn4JChallenge(tfa.webAuthnChallenge.get.data.toArray)
    val serverProperty = new ServerProperty(new Origin(origin), rpId, challenge, null)

    val registrationRequest = new RegistrationRequest(
      fromBase64(registration.attestationObject).toArray,
      fromBase64(registration.clientDataJson).toArray
    )

    val registrationParameters = new RegistrationParameters(
      serverProperty,
      // TODO MRB: do we care what public key algorithms to support?
      null,
      false,
      true
    )

    Attempt.catchNonFatal {
      val registrationData = webAuthnManager.parse(registrationRequest)
      webAuthnManager.validate(registrationData, registrationParameters)

      val authenticatorData = registrationData.getAttestationObject.getAuthenticatorData
      val attestedCredentialData = authenticatorData.getAttestedCredentialData

      val authenticator = WebAuthn4jAuthenticator(
        CredentialId(attestedCredentialData.getCredentialId.toVector),
        attestedCredentialData,
        transports = (Option(registrationData.getTransports)).map(_.asScala.toSet).getOrElse(Set.empty),
        counter = authenticatorData.getSignCount,
        authenticatorExtensions = authenticatorData.getExtensions,
        clientExtensions = registrationData.getClientExtensions
      )

      tfa.copy(
        webAuthnAuthenticators = tfa.webAuthnAuthenticators :+ authenticator,
        webAuthnChallenge = Some(Challenge.create(ssg))
      )
    } {
      case e: DataConversionException =>
        logger.warn(s"Webauthn registration parse failure for $username", e)
        ClientFailure("Webauthn registration failure")

      case e: ValidationException =>
        logger.warn(s"Webauthn registration validation failure for $username", e)
        ClientFailure("Webauthn registration failure")
    }
  }
}
