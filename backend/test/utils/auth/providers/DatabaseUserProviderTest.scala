package utils.auth.providers

import model.frontend.user.{PartialUser, TotpCodeRegistration}
import model.user.NewUser
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import play.api.libs.json.{JsBoolean, JsNumber, Json}
import play.api.mvc.{AnyContentAsFormUrlEncoded, Results}
import play.api.test.FakeRequest
import test.{AttemptValues, TestUserManagement}
import utils.attempt._

class DatabaseUserProviderTest extends AnyFreeSpec with Matchers with AttemptValues with Results  {
  import TestUserManagement._
  import test.fixtures.GoogleAuthenticator._

  def formParams(username: String, password: String, tfa: Option[String] = None): FakeRequest[AnyContentAsFormUrlEncoded] =
    FakeRequest("GET", "/endpoint").withBody(
      AnyContentAsFormUrlEncoded(List(
        Some("username" -> Seq(username)),
        Some("password" -> Seq(password)),
        tfa.map(v => "tfa" -> Seq(v))
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
          formParams(username = "bob", password = defaultPassword),
          sampleEpoch
        )

        authResult.successValue shouldBe PartialUser("bob", "Bob Bob")
      }

      "authentication fails when the user is not enrolled in 2FA when 2FA is required" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserNo2fa("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = defaultPassword),
          sampleEpoch
        )

        authResult.failureValue shouldBe MisconfiguredAccount("2FA is required but user is not enrolled")
      }

      "authentication fails when the password is right but 2FA is required" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserNo2fa("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = defaultPassword),
          sampleEpoch
        )

        authResult.failureValue shouldBe SecondFactorRequired("2FA code required")
      }

      "authentication fails when the password is right but 2FA is wrong" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = defaultPassword, tfa = Some(sampleAnswer)),
          sampleEpoch
        )

        authResult.failureValue shouldBe SecondFactorRequired("2FA code not valid")
      }

      "authentication succeeds when the password and 2FA are right" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))

        val authResult = userProvider.authenticate(
          formParams(username = "bob", password = defaultPassword, tfa = Some(sampleAnswer)),
          sampleEpoch
        )

        authResult.successValue shouldBe PartialUser("bob", "Bob Bob")
      }
    }

    "createUser" - {
      "fails if username does not match record in database" in {
        val (userProvider, _) = makeUserProvider(require2fa = true)

        val result = userProvider.createUser("bob", Json.toJson(NewUser("sheila", defaultPassword)))
        result.failureValue shouldBe ClientFailure("Username in URL didn't match that in payload.")
      }

      "fails if temporary password does not meet requirements" in {
        val (userProvider, _) = makeUserProvider(require2fa = true)

        val result = userProvider.createUser("bob", Json.toJson(NewUser("sheila", "a")))
        result.failureValue shouldBe ClientFailure(s"Provided password too short, must be at least ${userProvider.config.minPasswordLength} characters")
      }

      "creates user and generates initial 2fa configuration" in {
        val (userProvider, _) = makeUserProvider(require2fa = true)

        val result = userProvider.createUser("bob", Json.toJson("bob", defaultPassword))
        result.successValue shouldBe PartialUser("bob", "New User")

        val tfaParams = userProvider.get2faRegistrationParameters(
          formParams(username = "bob", password = defaultPassword),
          sampleEpoch,
          "test-instance"
        ).successValue

        tfaParams.totpSecret shouldBe sampleSecret.toBase32
        tfaParams.totpUrl shouldBe s"otpauth://totp/bob?secret=${sampleSecret.toBase32}&issuer=giant%20(test-instance)"
      }
    }

    "registerUser" - {
      "succeeds when 2FA not required" in {
        val (userProvider, users) = makeUserProvider(require2fa = false, unregisteredUserNo2fa("bob"))

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> defaultPassword,
          "newPassword" -> defaultPassword,
          "displayName" -> "Bob Bob Ricard"
        ), sampleEpoch)

        result.successValue

        val bob = users.getUser("bob").successValue
        bob.registered shouldBe true
        bob.displayName shouldBe Some("Bob Bob")
        bob.password shouldNot be(Some(defaultPasswordHashed))
      }

      "fails when 2fa is required and no method has been registered" in {
        val (userProvider, _) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> defaultPassword,
          "newPassword" -> defaultPassword,
          "displayName" -> "Bob Bob",
          "tfa" -> sampleAnswer
        ), sampleEpoch)

        result.failureValue shouldBe SecondFactorRequired("2FA enrollment is required")
      }

      "succeeds when 2FA is required and a method has been registered" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, unregisteredUserNo2fa("bob"))

        val register2faResult = userProvider.register2faMethod(
          formParams(username = "bob", password = defaultPassword),
          sampleEpoch,
          TotpCodeRegistration(sampleAnswer)
        )

        register2faResult.successValue.totp shouldBe true

        val user2fa = users.getUser2fa("bob").successValue
        user2fa.activeTotpSecret should contain(sampleSecret)
        user2fa.inactiveTotpSecret should not be empty
        user2fa.inactiveTotpSecret should not contain(sampleSecret)

        val registerUserResult = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> defaultPassword,
          "newPassword" -> defaultPassword,
          "displayName" -> "Bob Bob",
          "tfa" -> sampleAnswer
        ), sampleEpoch)

        registerUserResult.successValue

        val bob2 = users.getUser("bob").successValue
        bob2.registered shouldBe true
        bob2.displayName shouldBe Some("Bob Bob")
        bob2.password should not be Some(defaultPasswordHashed)
      }

      "fails when password is wrong" in {
        val (userProvider, users) = makeUserProvider(require2fa = false, unregisteredUserNo2fa("bob"))
        val unregisteredBob = users.getUser("bob").successValue

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> "wrongpassword",
          "newPassword" -> defaultPassword,
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
          "previousPassword" -> defaultPassword,
          "newPassword" -> "a",
          "displayName" -> "Bob Bob"
        ), sampleEpoch)

        result.failureValue shouldBe ClientFailure("Provided password too short, must be at least 8 characters")

        users.getUser("bob").successValue shouldBe unregisteredBob
      }

      "fails when 2FA is wrong" in {
        val (userProvider, users) = makeUserProvider(require2fa = true, registeredUserTotp("bob"))
        val unregisteredBob = users.getUser("bob").successValue

        val result = userProvider.registerUser(Json.obj(
          "username" -> "bob",
          "previousPassword" -> defaultPassword,
          "newPassword" -> defaultPassword,
          "displayName" -> "Bob Bob",
          "tfa" -> "123456"
        ), sampleEpoch)

        result.failureValue shouldBe ClientFailure("Sample 2FA code wasn't valid, check the time on your device")

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

//    "get2faRegistrationParameters" in {
//      "fails when username wrong" in {
//        ???
//      }
//
//      "fails when password wrong" in {
//        ???
//      }
//
//      "returns existing inactive totp secret" in {
//        ???
//      }
//
//      "generates inactive totp secret if the user doesn't already have one" in {
//        ???
//      }
//
//      "returns existing webauthn user handle" in {
//        ???
//      }
//
//      "generates webauthn user handle if the user doesn't already have one" in {
//        ???
//      }
//
//      "returns existing webauthn challenge" in {
//        ???
//      }
//
//      "returns data without 2fa if 2fa required but user is not yet registered" in {
//        ???
//      }
//
//      "fails when 2fa incorrect if 2fa required and user already registered" in {
//        ???
//      }
//    }
//
//    "get2faChallengeParameters" - {
//      "fails when username wrong" in {
//        ???
//      }
//
//      "fails when password wrong" in {
//        ???
//      }
//
//      "fails when user is not yet registered" in {
//        ???
//      }
//
//      "fails when 2fa is not required and user has no 2fa registered" in {
//        ???
//      }
//
//      "fails when 2fa is incorrect if 2fa is not required but user has registered 2fa anyway" {
//        ???
//      }
//
//      "fails when 2fa is incorrect if 2fa required" in {
//        ???
//      }
//
//      "returns data when 2fa is not required but user has registered 2fa anyway" in {
//        ???
//      }
//
//      "returns data when 2fa required" in {
//        ???
//      }
//
//      "returns a new webauthn challenge for each call" in {
//        ???
//      }
//    }
//
//    "register2faMethod" - {
//      "fails when username wrong" in {
//        ???
//      }
//
//      "fails when password wrong" in {
//        ???
//      }
//
//      "fails when 2fa is incorrect if user is registered and 2fa is required" in {
//        ???
//      }
//
//      "fails when 2fa is incorrect if 2fa is not required but user wants to anyway" {
//        ???
//      }
//
//      "fails when 2fa is incorrect if 2fa required" in {
//        ???
//      }
//
//      "registers 2fa method when 2fa is not required but user wants to anyway" in {
//        ???
//      }
//
//      "registers 2fa method when 2fa required" in {
//        ???
//      }
//
//      "registers 2fa method when user is unregistered and has no existing tfa" in {
//        ???
//      }
//    }

    // TODO MRB: add more tests (possibly integration tests rather than here?)
    //  - reset totp code (triggered by the user)
    //  - reset totp code (triggered by the admin, can't log in again until re-registered)
  }
}
