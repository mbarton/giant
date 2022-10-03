package utils.auth.webauthn

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.exception.DataConversionException
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.{DefaultChallenge => WebAuthn4JChallenge}
import com.webauthn4j.data.{RegistrationParameters, RegistrationRequest}
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.validator.exception.ValidationException
import model.frontend.user.WebAuthnPublicKeyRegistration
import model.user.DBUser2fa
import utils.Logging
import utils.attempt._
import utils.auth.totp.{Algorithm, SecureSecretGenerator}

import java.util.Base64

object WebAuthn extends Logging {
  private val cborObjectMapper = new ObjectMapper(new CBORFactory())
  private val webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager()

  // TODO MRB: how to determine these?
  val origin = "http://localhost:3000"
  val rpId = "localhost"

  // TODO MRB: what else should we support?
  val supportedAlg = -7 // ECDSA w/ SHA-256 https://www.iana.org/assignments/cose/cose.xhtml#algorithms

  // It is RECOMMENDED to let the user handle be 64 random bytes, and store this value in the user’s account
  // https://www.w3.org/TR/webauthn-2/#sctn-user-handle-privacy
  case class UserHandle(data: Vector[Byte])
  object UserHandle {
    def apply(data: Vector[Byte]): UserHandle = {
      assert(data.length == 64)
      new UserHandle(data)
    }

    def create(ssg: SecureSecretGenerator): UserHandle = {
      UserHandle(ssg.createRandomSecret(Algorithm.HmacSHA512).data)
    }
  }

  // Challenges SHOULD therefore be at least 16 bytes long.
  // https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges
  case class Challenge(data: Vector[Byte])
  object Challenge {
    def apply(data: Vector[Byte]): Challenge = {
      assert(data.length == 32)
      new Challenge(data)
    }

    def create(ssg: SecureSecretGenerator): Challenge = {
      Challenge(ssg.createRandomSecret(Algorithm.HmacSHA256).data)
    }
  }

  // TODO MRB: just use base64 url everywhere
  def toBase64(data: Vector[Byte]): String = Base64.getEncoder.encodeToString(data.toArray)

  def fromBase64(data: String): Vector[Byte] = Base64.getDecoder.decode(data).toVector

  def fromBase64Url(data: String): Vector[Byte] = Base64.getUrlDecoder.decode(data).toVector

  def verifyRegistration(username: String, tfa: DBUser2fa, registration: WebAuthnPublicKeyRegistration): Attempt[DBUser2fa] = {
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

      throw new Error("TODO: save the results!!")
    } {
      case e: DataConversionException =>
        logger.warn(s"Webauthn registration parse failure for $username", e)
        ClientFailure("Webauthn registration failure")

      case e: ValidationException =>
        logger.warn(s"Webauthn registration validation failure for $username", e)
        ClientFailure("Webauthn registration failure")
    }
  }

//  def verifyRegistration(username: String, tfa: DBUser2fa, registration: WebAuthnPublicKeyRegistration)(implicit ec: ExecutionContext): Attempt[DBUser2fa] = for {
//    // 7.1. Registering a New Credential https://w3c.github.io/webauthn/#sctn-registering-a-new-credential
//
//    //  5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
//    //  6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
//    clientDataJson <- parseClientDataJson(registration.clientDataJson)
//
//    //  7. Verify that the value of C.type is webauthn.create.
//    _ <- check(clientDataJson.`type` == "webauthn.create", s"Unknown type ${clientDataJson.`type`}")
//
//    //  8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
//    challenge = WebAuthn.Challenge(WebAuthn.fromBase64Url(clientDataJson.challenge))
//    _ <- check(tfa.webAuthnChallenge.contains(challenge), "Incorrect challenge")
//
//    //  9. Verify that the value of C.origin matches the Relying Party's origin.
//    // TODO MRB: how can we accurately know origin?
//
//    //  10. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
//    // TODO MRB: this
//
//    //  11. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
//    attestationObject <- parseAttestationObject(registration.attestationObject)
//
//    //  12. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
//    // TODO MRB: how can we accurately know the origin (domain) to calculate this
//
//    //  13. Verify that the UP bit of the flags in authData is set.
//    _ <- check(attestationObject.authData.userPresent, "UP bit not set")
//
//    //  17. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
//    _ <- check(attestationObject.authData.attestedCredentialData.nonEmpty, "No attestationCredentialData")
//
//    alg = attestationObject.authData.attestedCredentialData.get.credentialPublicKey.alg
//    _ <- check(alg == supportedAlg, s"Unsupported alg $alg")
//
//    //  19. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values
//    _ <- check(attestationObject.fmt == "none", s"Unsupported attestation statement format ${attestationObject.fmt}")
//
//
//
//    _ <- Attempt.Left[DBUser2fa](UnsupportedOperationFailure("TODO: implement the rest of webauthn. fmt: " + attestationObject.fmt))
//  } yield tfa
}
