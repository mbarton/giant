package users

import test.integration.Neo4jTestService
import model.user.{BCryptPassword, DBUser, DBUser2fa, UserPermissions, WebAuthnPublicKey}
import org.scalamock.scalatest.MockFactory
import services.annotations.Annotations
import services.index.{Index, Pages}
import services.manifest.Neo4jManifest
import services.users.Neo4jUserManagement
import test.fixtures.GoogleAuthenticator
import utils.Logging

import scala.concurrent.ExecutionContext.Implicits.global
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import utils.attempt.Attempt
import utils.auth.totp.{SecureSecretGenerator, Totp}
import utils.auth.webauthn.WebAuthn

class Neo4jUserManagementITest extends AnyFreeSpec with Matchers with Neo4jTestService with Logging with MockFactory {
  "Neo4JUserManagement" - {
    val user = DBUser("test", displayName = None, password = None, Some(1234), registered = false)
    val user2 = DBUser("test2", displayName = None, password = None, Some(1234), registered = false)

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
        users.registerUser(user.username, displayName, password).successValue shouldBe expected
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
        before.webAuthnPublicKeys shouldBe empty

        users.setUser2fa(username, before).successValue

        val after = users.getUser2fa(username).successValue

        after.activeTotpSecret shouldBe empty
        after.inactiveTotpSecret should contain(before.inactiveTotpSecret.get)
        after.webAuthnChallenge should contain(before.webAuthnChallenge.get)
        after.webAuthnUserHandle should contain(before.webAuthnUserHandle.get)
        before.webAuthnPublicKeys shouldBe empty
      }
    }

    "Can save 2fa config with webauthn keys" in {
      new TestSetup {
        val username = user.username

        val key1 = WebAuthnPublicKey(Vector.fill(1)(1.toByte), Vector.fill(2)(2.toByte))
        val key2 = WebAuthnPublicKey(Vector.fill(3)(3.toByte), Vector.fill(4)(4.toByte))

        val before = DBUser2fa.initial(ssg, totp).copy(webAuthnPublicKeys = List(key1, key2))

        users.setUser2fa(username, before).successValue

        val after = users.getUser2fa(username).successValue
        val keysAfter = after.webAuthnPublicKeys.toSet

        keysAfter should contain only(key1, key2)
      }
    }

    "Can save webauthn keys for multiple users" in {
      new TestSetup {
        val key1 = WebAuthnPublicKey(Vector.fill(1)(10.toByte), Vector.fill(2)(12.toByte))
        val key2 = WebAuthnPublicKey(Vector.fill(3)(13.toByte), Vector.fill(4)(14.toByte))

        val user1TfaBefore = DBUser2fa.initial(ssg, totp).copy(webAuthnPublicKeys = List(key1))
        val user2TfaBefore = DBUser2fa.initial(ssg, totp).copy(webAuthnPublicKeys = List(key2))

        users.setUser2fa(user.username, user1TfaBefore).successValue
        users.setUser2fa(user2.username, user2TfaBefore).successValue

        val user1TfaAfter = users.getUser2fa(user.username).successValue
        val user2TfaAfter = users.getUser2fa(user2.username).successValue

        user1TfaAfter shouldBe user1TfaBefore
        user2TfaAfter shouldBe user2TfaBefore
      }
    }
  }

  class TestSetup {
    val manifest = Neo4jManifest.setupManifest(neo4jDriver, global, neo4jQueryLoggingConfig).right.value

    val index = stub[Index]
    val pages = stub[Pages]

    val annotations = stub[Annotations]

    val totp = Totp.googleAuthenticatorInstance()
    val ssg = new SecureSecretGenerator

    val users = Neo4jUserManagement(neo4jDriver, global, neo4jQueryLoggingConfig, manifest, index, pages, annotations)
  }
}
