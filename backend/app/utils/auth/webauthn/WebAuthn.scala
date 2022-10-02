package utils.auth.webauthn

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import model.frontend.user.WebAuthnPublicKeyRegistration
import model.user.DBUser2fa
import play.api.libs.json.Json
import utils.Logging
import utils.attempt._
import utils.auth.totp.{Algorithm, SecureSecretGenerator}

import java.nio.ByteBuffer
import java.util.Base64
import scala.concurrent.ExecutionContext

object WebAuthn extends Logging {
  private val cborObjectMapper = new ObjectMapper(new CBORFactory())

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

  // https://w3c.github.io/webauthn/#dictionary-client-data
  case class ClientData(`type`: String, challenge: String, origin: String)

  // COSE Key (https://www.rfc-editor.org/rfc/rfc8152#section-7)
  case class CredentialPublicKey(alg: Int)

  // https://w3c.github.io/webauthn/#sctn-attested-credential-data
  case class AttestedCredentialData(aaguid: Vector[Byte], credentialId: Vector[Byte], credentialPublicKey: CredentialPublicKey)

  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  case class AuthenticatorData(rpIdHash: Vector[Byte], userPresent: Boolean, userVerified: Boolean,
                               backupEligibility: Boolean, backupState: Boolean,
                               extensionData: Boolean, signCount: Int, attestedCredentialData: Option[AttestedCredentialData])

  // https://w3c.github.io/webauthn/#dom-authenticatorattestationresponse-attestationobject
  case class AttestationObject(fmt: String, authData: AuthenticatorData)


  // TODO MRB: just use base64 url everywhere
  def toBase64(data: Vector[Byte]): String = Base64.getEncoder.encodeToString(data.toArray)

  def fromBase64(data: String): Vector[Byte] = Base64.getDecoder.decode(data).toVector

  def fromBase64Url(data: String): Vector[Byte] = Base64.getUrlDecoder.decode(data).toVector

  def verifyRegistration(username: String, tfa: DBUser2fa, registration: WebAuthnPublicKeyRegistration)(implicit ec: ExecutionContext): Attempt[DBUser2fa] = for {
    // 7.1. Registering a New Credential https://w3c.github.io/webauthn/#sctn-registering-a-new-credential

    //  5. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.
    //  6. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.
    clientDataJson <- parseClientDataJson(registration.clientDataJson)

    //  7. Verify that the value of C.type is webauthn.create.
    _ <- check(clientDataJson.`type` == "webauthn.create", s"Unknown type ${clientDataJson.`type`}")

    //  8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    challenge = WebAuthn.Challenge(WebAuthn.fromBase64Url(clientDataJson.challenge))
    _ <- check(tfa.webAuthnChallenge.contains(challenge), "Incorrect challenge")

    //  9. Verify that the value of C.origin matches the Relying Party's origin.
    // TODO MRB: how can we accurately know origin?

    //  10. Let hash be the result of computing a hash over response.clientDataJSON using SHA-256.
    // TODO MRB: this

    //  11. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.
    attestationObject <- parseAttestationObject(registration.attestationObject)

    //  12. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
    // TODO MRB: how can we accurately know the origin (domain) to calculate this

    //  13. Verify that the UP bit of the flags in authData is set.
    _ <- check(attestationObject.authData.userPresent, "UP bit not set")

    //  17. Verify that the "alg" parameter in the credential public key in authData matches the alg attribute of one of the items in options.pubKeyCredParams.
    _ <- check(attestationObject.authData.attestedCredentialData.nonEmpty, "No attestationCredentialData")

    alg = attestationObject.authData.attestedCredentialData.get.credentialPublicKey.alg
    _ <- check(alg == supportedAlg, s"Unsupported alg $alg")

    //  19. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values
    _ <- check(attestationObject.fmt == "none", s"Unsupported attestation statement format ${attestationObject.fmt}")



    _ <- Attempt.Left[DBUser2fa](UnsupportedOperationFailure("TODO: implement the rest of webauthn. fmt: " + attestationObject.fmt))
  } yield tfa

  private def parseClientDataJson(input: String): Attempt[ClientData] =
    Json.parse(WebAuthn.fromBase64(input).toArray).validate(Json.reads[ClientData]).toAttempt

  private def parseAttestationObject(input: String): Attempt[AttestationObject] = Attempt.catchNonFatalBlasé {
    val cbor = WebAuthn.fromBase64(input).toArray
    val obj = cborObjectMapper.readTree(cbor)

    val fmt = obj.get("fmt").asText()
    val authData = parseAuthData(ByteBuffer.wrap(obj.get("authData").binaryValue()))

    AttestationObject(fmt, authData)
  }

  private def parseAuthData(buf: ByteBuffer): AuthenticatorData = {
    val rpIdHash = new Array[Byte](32)
    buf.get(rpIdHash)

    val flags = buf.get()
    val signCount = buf.getInt

    val attestedCredentialDataIncluded = ((flags >> 6) & 1) == 1
    val attestedCredentialData = if(attestedCredentialDataIncluded) {
      val aaguid = new Array[Byte](16)
      buf.get(aaguid)

      val credentialIdLength = buf.getShort
      val credentialId = new Array[Byte](credentialIdLength)
      buf.get(credentialId)

      // TODO MRB: also parse extension data if available
      val credentialPublicKeyBytes = new Array[Byte](buf.remaining())
      buf.get(credentialPublicKeyBytes)

      val credentialPublicKeyObj = cborObjectMapper.readTree(credentialPublicKeyBytes)
      val credentialPublicKey = CredentialPublicKey(
        credentialPublicKeyObj.get("3").asInt()
      )

      Some(AttestedCredentialData(aaguid.toVector, credentialId.toVector, credentialPublicKey))
    } else {
      None
    }

    AuthenticatorData(
      rpIdHash = rpIdHash.toVector,
      userPresent = (flags & 1) == 1,
      userVerified = ((flags >> 2) & 1) == 1,
      backupEligibility = ((flags >> 3) & 1) == 1,
      backupState = ((flags >> 4) & 1) == 1,
      extensionData = ((flags >> 7) & 1) == 1,
      signCount = signCount,
      attestedCredentialData
    )
  }

  private def check(f: => Boolean, err: => String): Attempt[Unit] = if(f) { Attempt.Right(()) } else { Attempt.Left(ClientFailure(err)) }
}
