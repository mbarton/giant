package utils.auth.providers

import model.frontend.user.{PartialUser, TotpCodeRegistration}
import model.user.NewUser
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import play.api.libs.json.{JsBoolean, JsNumber, Json}
import play.api.mvc.{AnyContentAsFormUrlEncoded, Results}
import play.api.test.FakeRequest
import test.{AttemptValues, TestUserManagement, TestUserRegistration}
import utils.attempt.{LoginFailure, _}
import utils.auth.totp.{Base32Secret, Totp}
import utils.auth.webauthn.WebAuthn

class DatabaseUserProviderTest extends AnyFreeSpec with Matchers with AttemptValues with Results  {
  import TestUserManagement._
  import test.fixtures.GoogleAuthenticator._

  def formParams(username: String, password: String, tfa: Option[String] = None): FakeRequest[AnyContentAsFormUrlEncoded] =
    FakeRequest("GET", "/endpoint").withBody(
      AnyContentAsFormUrlEncoded(List(
        Some("username" -> Seq(username)),
        Some("password" -> Seq(password)),
        tfa.map(v => "tfa" -> Seq(v)),
      ).flatten.toMap)
    )

  "DatabaseUserProvider" - {
    "client config is built correctly" in {
      val (userProvider, _) = makeUserProvider(require2fa = true)

      userProvider.clientConfig shouldBe Map(
        "require2fa" -> JsBoolean(true),
        "minPasswordLength" -> JsNumber(userProvider.config.minPasswordLength)
      )
    }

    "authentication" - {

      "authentication fails when the user is not in database" in {
        val (userProvider, _) = makeUserProvider(require2fa = true)

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = "bobby"),
          sampleEpoch
        )

        authResult.failureValue shouldBe UserDoesNotExistFailure("bob")
      }


      "authentication fails when the password is wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserNo2fa("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = "wrong"),
          sampleEpoch
        )

        authResult.failureValue shouldBe LoginFailure("Incorrect password")
      }

      "authentication succeeds when the password is right and 2FA isn't required" in {
        val (userProvider, _) = makeUserProvider(require2fa = false,
          registeredUserNo2fa("bob", Some("Bob Bob")))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = testPassword),
          sampleEpoch
        )

        authResult.successValue shouldBe PartialUser("bob", "Bob Bob")
      }

      "authentication fails when the user is not enrolled in 2FA when 2FA is required" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserNo2fa("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = testPassword),
          sampleEpoch
        )

        authResult.failureValue shouldBe SecondFactorRequired("2FA enrollment is required")
      }

      "authentication fails when the password is right but 2FA is required" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = testPassword),
          sampleEpoch
        )

        authResult.failureValue shouldBe SecondFactorRequired("2FA code required")
      }

      "authentication fails when the password is right but 2FA is wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = testPassword, tfa = Some("123456")),
          sampleEpoch
        )

        authResult.failureValue shouldBe ClientFailure("2FA code not valid")
      }

      "authentication succeeds when the password and 2FA are right" in {
        val (userProvider, _) = makeUserProvider(require2fa = true,
          registeredUserTotp("bob", displayName = Some("Bob Bob Ricard")))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = testPassword, tfa = Some(sampleAnswer)),
          sampleEpoch
        )

        authResult.successValue shouldBe PartialUser("bob", "Bob Bob Ricard")
      }
    }

    "createUser" - {
      "fails if username does not match record in database" in {
        val (userProvider, _) = makeUserProvider(require2fa = true)

        val result = userProvider.createUser("bob", Json.toJson(NewUser("sheila", testPassword)))
        result.failureValue shouldBe ClientFailure("Username in URL didn't match that in payload.")
      }

      "fails if temporary password does not meet requirements" in {
        val (userProvider, _) = makeUserProvider(require2fa = true)

        val result = userProvider.createUser("bob", Json.toJson(NewUser("bob", "a")))
        result.failureValue shouldBe ClientFailure(s"Provided password too short, must be at least ${userProvider.config.minPasswordLength} characters")
      }

      "creates user and generates initial 2fa configuration" in {
        val (userProvider, users) = makeUserProvider(require2fa = true)

        val result = userProvider.createUser("bob", Json.toJson(NewUser("bob", testPassword)))
        result.successValue shouldBe PartialUser("bob", "New User")

        val inactiveTotpSecret = users.getUser("bob").successValue.tfa.inactiveTotpSecret
        inactiveTotpSecret should not be empty

        val tfaParams = userProvider.get2faRegistrationParameters(
          formParams(username = "bob", password = testPassword),
          sampleEpoch
        ).successValue

        tfaParams.totpSecret shouldBe inactiveTotpSecret.get.toBase32
      }
    }

    "registerUser" - {
      "succeeds when 2FA not required" in {
        val (userProvider, users) = makeUserProvider(require2fa = false, unregisteredUserNo2fa("bob"))

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> testPassword,
          "newPassword" -> testPassword,
          "displayName" -> "Bob Bob Ricard"
        ), sampleEpoch)

        result.successValue

        val bob = users.getUser("bob").successValue
        bob.registered shouldBe true
        bob.displayName shouldBe Some("Bob Bob Ricard")
        bob.password shouldNot be(Some(testPasswordHashed))
      }

      "fails when password is wrong" in {
        val (userProvider, users) = makeUserProvider(require2fa = false, unregisteredUserNo2fa("bob"))
        val unregisteredBob = users.getUser("bob").successValue

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> "wrongpassword",
          "newPassword" -> testPassword,
          "displayName" -> "Bob Bob"
        ), sampleEpoch)

        result.failureValue shouldBe LoginFailure("Incorrect password")

        users.getUser("bob").successValue shouldBe unregisteredBob
      }

      "fails when new password is too short" in {
        val (userProvider, users) = makeUserProvider(require2fa = false, unregisteredUserNo2fa("bob"))
        val unregisteredBob = users.getUser("bob").successValue

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> testPassword,
          "newPassword" -> "a",
          "displayName" -> "Bob Bob"
        ), sampleEpoch)

        result.failureValue shouldBe ClientFailure("Provided password too short, must be at least 8 characters")

        users.getUser("bob").successValue shouldBe unregisteredBob
      }

      "fails when 2FA is wrong" in {
        val baseUser = registeredUserTotp("bob")
        val user = baseUser.copy(dbUser = baseUser.dbUser.copy(registered = false))

        val (userProvider, users) = makeUserProvider(require2fa = true, user)
        val unregisteredBob = users.getUser("bob").successValue

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> testPassword,
          "newPassword" -> testPassword,
          "displayName" -> "Bob Bob",
          "tfa" -> Json.obj(
            "type" -> "totp",
            "code" -> "123456"
          )
        ), sampleEpoch)

        result.failureValue shouldBe ClientFailure("2FA code not valid")

        users.getUser("bob").successValue shouldBe unregisteredBob
      }
    }

    "removeUser" in {
      val (userProvider, users) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

      userProvider.removeUser("bob").successValue
      users.getAllUsers shouldBe Nil
    }

    "updatePassword" - {
      "should update password" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))
        val hashedPasswordBefore = users.getUser("bob").successValue.password.get

        userProvider.updatePassword("bob", "myHarderToGuessPassword").successValue

        users.getUser("bob").successValue.password should not be Some(hashedPasswordBefore)
      }

      "should prevent setting a password that is too short" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))
        val hashedPasswordBefore = users.getUser("bob").successValue.password.get

        userProvider.updatePassword("bob", "2short").failureValue shouldBe
          ClientFailure("Provided password too short, must be at least 8 characters")

        users.getUser("bob").successValue.password shouldBe Some(hashedPasswordBefore)
      }
    }

    "get2faRegistrationParameters" - {
      "fails when username wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))

        val result = userProvider.get2faRegistrationParameters(formParams("ted", testPassword), sampleEpoch)

        result.failureValue shouldBe an[UserDoesNotExistFailure]
      }

      "fails when password wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))

        val result = userProvider.get2faRegistrationParameters(formParams("bob", "hello!"), sampleEpoch)

        result.failureValue shouldBe a[LoginFailure]
      }

      "returns existing inactive totp secret" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))
        val inactiveTotpSecret = users.getUser("bob").successValue.tfa.inactiveTotpSecret

        inactiveTotpSecret should not be empty

        val result = userProvider.get2faRegistrationParameters(formParams("bob", testPassword), sampleEpoch)
        result.successValue.totpSecret shouldBe inactiveTotpSecret.get.toBase32
      }

      "generates inactive totp secret if the user doesn't already have one" in {
        val baseUser = unregisteredUserNo2fa("bob")
        val user = baseUser.copy(dbUser = baseUser.dbUser.copy(tfa = baseUser.dbUser.tfa.copy(inactiveTotpSecret = None)))

        val (userProvider, users) = makeUserProvider(require2fa = true, user)

        val result = userProvider.get2faRegistrationParameters(formParams("bob", testPassword), sampleEpoch)
        result.successValue.totpSecret should not be empty

        val stored2fa = users.getUser("bob").successValue.tfa
        stored2fa.inactiveTotpSecret should contain(Base32Secret(result.successValue.totpSecret))
      }

      "returns existing webauthn user handle" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))
        val webAuthnUserHandle = users.getUser("bob").successValue.tfa.webAuthnUserHandle

        webAuthnUserHandle should not be empty

        val result = userProvider.get2faRegistrationParameters(formParams("bob", testPassword), sampleEpoch)
        result.successValue.webAuthnUserHandle shouldBe WebAuthn.toBase64(webAuthnUserHandle.get.data)
      }

      "generates webauthn user handle if the user doesn't already have one" in {
        val baseUser = unregisteredUserNo2fa("bob")
        val user: TestUserRegistration = baseUser.copy(dbUser = baseUser.dbUser.copy(
          tfa = baseUser.dbUser.tfa.copy(webAuthnUserHandle = None)))

        val (userProvider, users) = makeUserProvider(require2fa = true, user)

        val result = userProvider.get2faRegistrationParameters(formParams("bob", testPassword), sampleEpoch)
        val webAuthnUserHandle = result.successValue.webAuthnUserHandle

        val stored2fa = users.getUser("bob").successValue.tfa
        WebAuthn.toBase64(stored2fa.webAuthnUserHandle.get.data) shouldBe webAuthnUserHandle
      }

      "returns existing webauthn challenge" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))
        val webAuthnUserHandle = users.getUser("bob").successValue.tfa.webAuthnUserHandle

        webAuthnUserHandle should not be empty

        val result = userProvider.get2faRegistrationParameters(formParams("bob", testPassword), sampleEpoch)
        result.successValue.webAuthnUserHandle shouldBe WebAuthn.toBase64(webAuthnUserHandle.get.data)
      }

      "generates webauthn challenge if the user doesn't already have one" in {
        val baseUser = unregisteredUserNo2fa("bob")
        val user: TestUserRegistration = baseUser.copy(dbUser = baseUser.dbUser.copy(
          tfa = baseUser.dbUser.tfa.copy(webAuthnChallenge = None)))

        val (userProvider, users) = makeUserProvider(require2fa = true, user)

        val result = userProvider.get2faRegistrationParameters(formParams("bob", testPassword), sampleEpoch)
        val webAuthnChallenge = result.successValue.webAuthnChallenge

        val stored2fa = users.getUser("bob").successValue.tfa
        WebAuthn.toBase64(stored2fa.webAuthnChallenge.get.data) shouldBe webAuthnChallenge
      }
    }

    "get2faChallengeParameters" - {
      "fails when username wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val result = userProvider.get2faChallengeParameters(formParams("ted", testPassword), sampleEpoch)

        result.failureValue shouldBe an[UserDoesNotExistFailure]
      }

      "fails when password wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val result = userProvider.get2faChallengeParameters(formParams("bob", "hello!"), sampleEpoch)

        result.failureValue shouldBe a[LoginFailure]
      }

      "fails when user is not yet registered" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))

        val result = userProvider.get2faChallengeParameters(formParams("bob", testPassword), sampleEpoch)

        result.failureValue shouldBe a[LoginFailure]
      }

      "returns data even when 2fa is not required" in {
        val (userProvider, _) = makeUserProvider(require2fa = false, registeredUserNo2fa("bob"))

        val result = userProvider.get2faChallengeParameters(formParams("bob", testPassword), sampleEpoch)
        result.successValue
      }

      "returns a new webauthn challenge for each call" in {
        val (userProvider, users) = makeUserProvider(require2fa = false, registeredUserNo2fa("bob"))

        val first = userProvider.get2faChallengeParameters(formParams("bob", testPassword), sampleEpoch).successValue
        val second = userProvider.get2faChallengeParameters(formParams("bob", testPassword), sampleEpoch).successValue

        second.webAuthnChallenge should not be(first.webAuthnChallenge)

        val challenge = users.getUser("bob").successValue.tfa.webAuthnChallenge
        challenge should not be empty

        second.webAuthnChallenge shouldBe WebAuthn.toBase64(challenge.get.data)
      }
    }

    "register2faMethod" - {
      "registers totp" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, registeredUserNo2fa("bob"))

        val result = userProvider.register2faMethod("bob", TotpCodeRegistration(sampleAnswer), sampleEpoch)
        result.successValue

        users.getUser("bob").successValue.tfa.activeTotpSecret should not be empty
      }

      "update totp code for existing user" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val inactiveTotpSecret = users.getUser("bob").successValue.tfa.inactiveTotpSecret.get
        val code = Totp.googleAuthenticatorInstance().generateList(inactiveTotpSecret, sampleEpoch)(scala.concurrent.ExecutionContext.global).successValue.head

        val result = userProvider.register2faMethod("bob", TotpCodeRegistration(code), sampleEpoch)
        result.successValue

        users.getUser("bob").successValue.tfa.activeTotpSecret should contain(inactiveTotpSecret)
      }
    }

    // TODO MRB: add more tests (possibly integration tests rather than here?)
    //  - reset totp code (triggered by the user)
    //  - reset totp code (triggered by the admin, can't log in again until re-registered)
    //  - e2e tests for getting params and registering 2fa (both unregistered and registered users)
  }
}
