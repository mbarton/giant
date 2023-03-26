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
import com.webauthn4j.data.{AuthenticationParameters, AuthenticationRequest, AuthenticatorTransport, RegistrationParameters, RegistrationRequest}
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.validator.exception.ValidationException
import model.user.DBUser2fa
import model.frontend.user.{WebAuthnChallengeResponse, WebAuthnPublicKeyRegistration}
import play.api.libs.json.{Format, JsArray, JsNumber, JsResult, JsString, JsValue, Json}
import utils.Logging
import utils.attempt._
import utils.auth.totp.{Algorithm, SecureSecretGenerator}

import scala.jdk.CollectionConverters._
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
    def encode(): String = toBase64Url(data)
  }
  object UserHandle {
    def apply(data: Vector[Byte]): UserHandle = {
      assert(data.length == 64)
      new UserHandle(data)
    }

    def create(ssg: SecureSecretGenerator): UserHandle = {
      UserHandle(ssg.createRandomSecret(Algorithm.HmacSHA512).data)
    }

    def decode(input: String): UserHandle = UserHandle(fromBase64Url(input))
  }

  // Challenges SHOULD therefore be at least 16 bytes long.
  // https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
  case class Challenge(data: Vector[Byte]) {
    def encode(): String = toBase64Url(data)
  }

  object Challenge {
    def apply(data: Vector[Byte]): Challenge = {
      assert(data.length == 32)
      new Challenge(data)
    }

    def create(ssg: SecureSecretGenerator): Challenge = {
      Challenge(ssg.createRandomSecret(Algorithm.HmacSHA256).data)
    }

    def decode(input: String): Challenge = Challenge(fromBase64Url(input))
  }

  case class CredentialId(data: Vector[Byte]) {
    def encode(): String = toBase64Url(data)
  }

  object CredentialId {
    def decode(input: String): CredentialId = CredentialId(fromBase64Url(input))
  }

  // https://webauthn4j.github.io/webauthn4j/en/#representation-of-an-authenticator
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
        attestedCredentialData <- (json \ "attestedCredentialData").validate[String].map { v => attestedCredentialDataConverter.convert(fromBase64Url(v).toArray) }
        transports <- (json \ "transports").validate[List[String]].map(_.map(AuthenticatorTransport.create)).map(_.toSet)
        counter <- (json \ "counter").validate[Long]
        authenticatorExtensions <- (json \ "authenticatorExtensions").validate[String].map { v =>
          webAuthnObjectConverter.getCborConverter.readValue[AuthenticationExtensionsAuthenticatorOutputs[_]](fromBase64Url(v).toArray, classOf[AuthenticationExtensionsAuthenticatorOutputs[_]])
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
          "attestedCredentialData" -> JsString(toBase64Url(attestedCredentialDataConverter.convert(o.attestedCredentialData).toVector)),
          "transports" -> JsArray(o.transports.map { t => JsString(t.toString) }.toList),
          "counter" -> JsNumber(o.counter),
          "authenticatorExtensions" -> JsString(toBase64Url(webAuthnObjectConverter.getCborConverter.writeValueAsBytes(o.authenticatorExtensions).toVector)),
          "clientExtensions" -> JsString(webAuthnObjectConverter.getJsonConverter.writeValueAsString(o.authenticatorExtensions))
        )
      }
    }

    def decode(input: String): WebAuthn4jAuthenticator = {
      Json.parse(input).as[WebAuthn4jAuthenticator](format.reads)
    }
  }

  private def toBase64Url(data: Vector[Byte]): String = Base64.getUrlEncoder.withoutPadding().encodeToString(data.toArray)

  private def fromBase64Url(data: String): Vector[Byte] = Base64.getUrlDecoder.decode(data).toVector

  def verifyRegistration(username: String, tfa: DBUser2fa, registration: WebAuthnPublicKeyRegistration, ssg: SecureSecretGenerator): Attempt[DBUser2fa] = {
    val challenge = new WebAuthn4JChallenge(tfa.webAuthnChallenge.get.data.toArray)
    val serverProperty = new ServerProperty(new Origin(origin), rpId, challenge, null)

    val registrationRequest = new RegistrationRequest(
      fromBase64Url(registration.attestationObject).toArray,
      fromBase64Url(registration.clientDataJson).toArray
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

  def verify(username: String, tfa: DBUser2fa, params: WebAuthnChallengeResponse): Attempt[Unit] = {
    val credentialId = WebAuthn.CredentialId.decode(params.id)

    val challenge = new WebAuthn4JChallenge(tfa.webAuthnChallenge.get.data.toArray)
    val serverProperty = new ServerProperty(new Origin(origin), rpId, challenge, null)

    val request = new AuthenticationRequest(
      credentialId.data.toArray,
      params.userHandle.map(WebAuthn.UserHandle.decode).map(_.data.toArray).orNull,
      WebAuthn.fromBase64Url(params.authenticatorData).toArray,
      WebAuthn.fromBase64Url(params.clientDataJson).toArray,
      null,
      WebAuthn.fromBase64Url(params.signature).toArray
    )

    tfa.webAuthnAuthenticators.find(_.id == credentialId) match {
      case Some(authenticator) =>
        val params = new AuthenticationParameters(
          serverProperty,
          authenticator.instance(),
          null,
          // user verification not required
          false,
          // user presence required
          true
        )

        Attempt.catchNonFatal {
          val authenticationData = webAuthnManager.parse(request)
          webAuthnManager.validate(authenticationData, params)

          // TODO MRB: update counter of the auth record (it's always zero for yubikeys anyway?)
          ()
        } {
          case e: DataConversionException =>
            logger.warn(s"Webauthn authentication parse failure for $username", e)
            ClientFailure("Webauthn authentication failure")

          case e: ValidationException =>
            logger.warn(s"Webauthn authentication validation failure for $username", e)
            ClientFailure("Webauthn authentication failure")
        }

      case None =>
        Attempt.Left(MisconfiguredAccount(s"Unknown credential id ${credentialId.encode()}"))
    }
  }
}
