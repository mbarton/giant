package users

import com.webauthn4j.data.attestation.authenticator.{AAGUID, AttestedCredentialData, EC2COSEKey}
import com.webauthn4j.data.extension.authenticator.{AuthenticationExtensionsAuthenticatorOutputs, RegistrationExtensionAuthenticatorOutput}
import com.webauthn4j.data.extension.client.{AuthenticationExtensionsClientOutputs, RegistrationExtensionClientOutput}
import model.user._
import org.scalamock.scalatest.MockFactory
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import services.annotations.Annotations
import services.index.{Index, Pages}
import services.manifest.Neo4jManifest
import services.users.Neo4jUserManagement
import test.TestUserManagement
import test.integration.Neo4jTestService
import utils.Logging
import utils.auth.totp.{Algorithm, SecureSecretGenerator, Totp}
import utils.auth.webauthn.WebAuthn

import java.util.UUID
import scala.concurrent.ExecutionContext.Implicits.global

class Neo4jUserManagementITest extends AnyFreeSpec with Matchers with Neo4jTestService with Logging with MockFactory {
  "Neo4JUserManagement" - {
    val user = TestUserManagement.unregisteredUserNo2fa("test").dbUser
    val user2 = TestUserManagement.unregisteredUserNo2fa("test2").dbUser

    val permissions = UserPermissions.bigBoss

    "Can create new users" in {
      new TestSetup {
        users.createUser(user, permissions).successValue shouldBe user
        users.createUser(user2, permissions).successValue shouldBe user2
      }
    }

    "Can create default resources when a new user registers" in {
      val displayName = "Test User"
      val password = Some(BCryptPassword("$1$1$1$"))

      val expected = user.copy(
        registered = true,
        displayName = Some(displayName),
        password = password,
      )

      new TestSetup {
        users.registerUser(user.username, displayName, password, None).successValue shouldBe expected
        users.getVisibleCollectionUrisForUser(user.username).successValue should be(Set(s"$displayName Documents"))
      }
    }

    "Can save initial default 2fa config" in {
      new TestSetup {
        val username = user.username
        val before = DBUser2fa.initial(ssg, totp)

        before.activeTotpSecret shouldBe empty
        before.inactiveTotpSecret should not be empty
        before.webAuthnChallenge should not be empty
        before.webAuthnUserHandle should not be empty
        before.webAuthnAuthenticators shouldBe empty

        users.setUser2fa(username, before).successValue

        val after = users.getUser(username).successValue.tfa

        after.activeTotpSecret shouldBe empty
        after.inactiveTotpSecret should contain(before.inactiveTotpSecret.get)
        after.webAuthnChallenge should contain(before.webAuthnChallenge.get)
        after.webAuthnUserHandle should contain(before.webAuthnUserHandle.get)
        before.webAuthnAuthenticators shouldBe empty
      }
    }

    "Can save 2fa config with webauthn keys" in {
      new TestSetup {
        val username = user.username

        val key1 = webAuthnAuthenticator()
        val key2 = webAuthnAuthenticator()

        val before = DBUser2fa.initial(ssg, totp).copy(webAuthnAuthenticators = List(key1, key2))

        users.setUser2fa(username, before).successValue

        val after = users.getUser(username).successValue.tfa
        val keysAfter = after.webAuthnAuthenticators

        val credentialIdsBefore = Set(key1.id, key2.id)
        val credentialIdsAfter = keysAfter.map(_.id).toSet

        credentialIdsAfter shouldBe credentialIdsBefore
      }
    }

    "Can save webauthn keys for multiple users" in {
      new TestSetup {
        val key1 = webAuthnAuthenticator()
        val key2 = webAuthnAuthenticator()

        val user1TfaBefore = DBUser2fa.initial(ssg, totp).copy(webAuthnAuthenticators = List(key1))
        val user2TfaBefore = DBUser2fa.initial(ssg, totp).copy(webAuthnAuthenticators = List(key2))

        users.setUser2fa(user.username, user1TfaBefore).successValue
        users.setUser2fa(user2.username, user2TfaBefore).successValue

        val user1CredentialIdsAfter = users.getUser(user.username).successValue.tfa.webAuthnAuthenticators.map(_.id)
        val user2CredentialIdsAfter = users.getUser(user2.username).successValue.tfa.webAuthnAuthenticators.map(_.id)

        user1CredentialIdsAfter should contain only(key1.id)
        user2CredentialIdsAfter should contain only(key2.id)
      }
    }
  }

  class TestSetup {
    val manifest = Neo4jManifest.setupManifest(neo4jDriver, global, neo4jQueryLoggingConfig).toOption.get

    val index = stub[Index]
    val pages = stub[Pages]

    val annotations = stub[Annotations]

    val totp = Totp.googleAuthenticatorInstance()
    val ssg = new SecureSecretGenerator

    val users = Neo4jUserManagement(neo4jDriver, global, neo4jQueryLoggingConfig, manifest, index, pages, annotations)

    def webAuthnAuthenticator(): WebAuthn.WebAuthn4jAuthenticator = {
      val credentialId = WebAuthn.CredentialId(ssg.createRandomSecret(Algorithm.HmacSHA256).data)

      WebAuthn.WebAuthn4jAuthenticator(
        id = credentialId,
        attestedCredentialData = new AttestedCredentialData(
          new AAGUID(UUID.randomUUID()),
          credentialId.data.toArray,
          EC2COSEKey.createFromUncompressedECCKey(Array.fill(65)(0))
        ),
        transports = Set.empty,
        counter = 0,
        authenticatorExtensions = new AuthenticationExtensionsAuthenticatorOutputs[RegistrationExtensionAuthenticatorOutput],
        clientExtensions = new AuthenticationExtensionsClientOutputs[RegistrationExtensionClientOutput]
      )
    }
  }
}
