package utils.auth.webauthn

import utils.auth.totp.{Algorithm, SecureSecretGenerator}

import java.util.Base64

object WebAuthn {
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

  def toBase64(data: Vector[Byte]): String = Base64.getEncoder.encodeToString(data.toArray)
  def fromBase64(data: String): Vector[Byte] = Base64.getDecoder.decode(data).toVector
}
