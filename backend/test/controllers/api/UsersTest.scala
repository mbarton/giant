package controllers.api

import akka.http.scaladsl.model.FormData
import akka.stream.Materializer
import akka.stream.testkit.NoMaterializer
import model.frontend.user.{TotpCodeRegistration, UserRegistration}
import model.manifest.Collection
import model.user
import model.user.{BCryptPassword, DBUser, NewUser, UserPermissions}
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import play.api.libs.json.{JsArray, JsObject, Json}
import play.api.mvc.{Action, AnyContentAsEmpty, Request, Results}
import play.api.test.FakeRequest
import play.api.test.Helpers._
import services.DatabaseAuthConfig
import services.users.UserManagement
import test.integration.Helpers.stubControllerComponentsAsUser
import test.{AttemptValues, TestUserManagement}
import utils.attempt.{ClientFailure, SecondFactorRequired}
import utils.auth.providers.DatabaseUserProvider
import utils.auth.totp.{Base32Secret, SecureSecretGenerator, Totp}
import utils.auth.webauthn.WebAuthn
import utils.auth.{PasswordHashing, PasswordValidator, TwoFactorAuth}

class UsersTest extends AnyFreeSpec with Matchers with Results with ScalaFutures with AttemptValues {
  import scala.concurrent.ExecutionContext.Implicits.global
  implicit val mat: Materializer = NoMaterializer

  private val hashing = new PasswordHashing(7)
  private val validator = new PasswordValidator(12)
  private val ssg = new SecureSecretGenerator()
  private val totp = Totp.googleAuthenticatorInstance()

  val paul = user.DBUser("paul", Some("Paul Chuckle"), Some(BCryptPassword("invalid")), None, registered = true)
  val barry = user.DBUser("barry", Some("Barry Chuckle"), Some(BCryptPassword("invalid")), None, registered = true)
  val users: Map[DBUser, (UserPermissions, List[Collection])] = Map(paul -> (UserPermissions.default, List.empty), barry -> (UserPermissions.default, List.empty))

  "UsersController" - {
    "list partial user information to punters" in {
      TestSetup(users + (paul -> (UserPermissions.bigBoss, List.empty), barry -> (UserPermissions.default, List.empty)), barry) { (controller, _) =>
        val result = controller.listUsers.apply(FakeRequest())
        val json = contentAsJson(result)

        val users = (json \ "users").as[JsArray].value
        users should have length 2

        users.collect { case user: JsObject =>
          user.fields.map(_._1) should contain only("username", "displayName")
        }
      }
    }

    "list full user information to admins" in {
      TestSetup(users + (paul -> (UserPermissions.bigBoss, List.empty)), paul) { (controller, _) =>
        val result = controller.listUsers.apply(FakeRequest())
        val json = contentAsJson(result)

        val users = (json \ "users").as[JsArray].value
        users should have length 2

        users.collect { case user: JsObject =>
          user.fields.map(_._1) should contain only("username", "displayName", "collections", "permissions")
        }
      }
    }

    "get user permissions" in {
      TestSetup(users + (paul -> (UserPermissions.bigBoss, List.empty)), paul) { (controller, _) =>
        val result = controller.getMyPermissions.apply(FakeRequest())
        val json = contentAsJson(result)

        json.as[UserPermissions] should be(UserPermissions.bigBoss)
      }

      TestSetup(users + (paul -> (UserPermissions.default, List.empty)), barry) { (controller, _) =>
        val result = controller.getMyPermissions.apply(FakeRequest())
        val json = contentAsJson(result)

        json.as[UserPermissions] should be(UserPermissions.default)
      }
    }

    "disallow operations without permission" in {
      TestSetup(users, paul) { (controller, _) =>
        def disallow[T](action: Action[T], body: T) = {
          val req: Request[T] = FakeRequest().withBody(body)
          val resp = action.apply(req)

          status(resp) should be(403)
        }

        disallow(controller.createUser("test"), Json.toJson(NewUser("test", "biglongpassword1234")))
        disallow(controller.removeUser(barry.username), AnyContentAsEmpty)

        disallow(controller.updateUserFullname(barry.username), Json.parse("""{"displayName": "test"}"""))
        disallow(controller.updateUserPassword(barry.username), Json.parse("""{"password": "biglongpassword1234"}"""))
      }
    }

    "create user that is flagged as not registered" in {
      TestSetup(users + (paul -> (UserPermissions.bigBoss, List.empty)), paul) { (controller, db) =>
        val req = FakeRequest().withBody(Json.toJson(NewUser("test", "biglongpassword1234")))

        status(controller.createUser("test").apply(req)) should be(200)

        val users = db.listUsers().asFuture.futureValue.right.get
        users.find(_._1.username == "test").map(_._1.registered) should contain(false)
      }
    }

    "the register user flow" - {
      import test.fixtures.GoogleAuthenticator._
      val originalPasswordText = "bob"
      val originalPassword = BCryptPassword("$2y$14$QfKVhpRMSe1VXi.ghHLJguCY6CmSA.ipNrg8JJZok5xhUxM5wDIem")
      val bob = DBUser("bob", Some("Spongebob"), Some(originalPassword), None, registered = false)

      "with require2FA set to false" - {
        "password and registered flag should be updated" in {
          val users = TestUserManagement(List(bob))
          val tfa = new TwoFactorAuth(require2fa = false, totp, users)
          val userProvider = new DatabaseUserProvider(null, hashing, users, totp, ssg, validator, tfa)

          val registration = UserRegistration("bob", originalPasswordText, "Spongebob", "longPassword", None)
          val result = userProvider.registerUser(Json.toJson(registration), sampleEpoch)

          result.successValue shouldBe (())
          val newBob = users.getAllUsers.find(_.username == "bob").get
          newBob.registered shouldBe true
          newBob.password should not be originalPassword
        }

        "2FA can be successfully enabled and secret set" in {
          val users = TestUserManagement(List(bob))
          val tfa = new TwoFactorAuth(require2fa = true, totp, users)
          val userProvider = new DatabaseUserProvider(null, hashing, users, totp, ssg, validator, tfa)

          val requestWithAuthData = FakeRequest().withFormUrlEncodedBody(
            "username" -> bob.username,
            "password" -> "bob",
            "tfa" -> sampleAnswers.head
          )

          val tfaRegistrationParams = userProvider.get2faRegistrationParameters(requestWithAuthData, sampleEpoch, "giant").successValue
          val placeholderTfaData = users.getUser2fa(bob.username).successValue

          placeholderTfaData.activeTotpSecret shouldBe empty
          placeholderTfaData.inactiveTotpSecret should contain(Base32Secret(tfaRegistrationParams.totpSecret))
          placeholderTfaData.webAuthnPublicKeys shouldBe empty
          placeholderTfaData.webAuthnUserHandle should not be empty
          placeholderTfaData.webAuthnChallenge should not be empty

          val tfaConfiguration = userProvider.register2faMethod(requestWithAuthData, sampleEpoch, TotpCodeRegistration(sampleAnswers.head)).successValue
          tfaConfiguration.totp should be(true)
          tfaConfiguration.webAuthnChallenge should be(WebAuthn.toBase64(placeholderTfaData.webAuthnChallenge.get.data))

          val storedTfaData = users.getUser2fa(bob.username).successValue
          storedTfaData.activeTotpSecret should contain(Base32Secret(tfaRegistrationParams.totpSecret))
          storedTfaData.inactiveTotpSecret should not be empty
          storedTfaData.webAuthnPublicKeys shouldBe empty
          storedTfaData.webAuthnUserHandle should be(placeholderTfaData.webAuthnUserHandle)
          storedTfaData.webAuthnChallenge should be(placeholderTfaData.webAuthnChallenge)
        }

        "fails if the 2FA code isn't valid" in {
          val users = TestUserManagement(List(bob))
          val tfa = new TwoFactorAuth(require2fa = true, totp, users)
          val userProvider = new DatabaseUserProvider(null, hashing, users, totp, ssg, validator, tfa)

          val requestWithAuthData = FakeRequest().withFormUrlEncodedBody(
            "username" -> bob.username,
            "password" -> "bob",
            "tfa" -> sampleAnswers.head
          )

          userProvider.get2faRegistrationParameters(requestWithAuthData, sampleEpoch, "giant").successValue
          val result = userProvider.register2faMethod(requestWithAuthData, sampleEpoch, TotpCodeRegistration(sampleAnswers.head))

          result.failureValue shouldBe ClientFailure("Sample 2FA code wasn't valid, check the time on your device")
        }
      }

      "with require2FA set to true" - {
        "fails with a lack of 2FA information" in {
          val users = TestUserManagement(List(bob))
          val tfa = new TwoFactorAuth(require2fa = true, totp, users)
          val userProvider = new DatabaseUserProvider(null, hashing, users, totp, ssg, validator, tfa)

          val registration = UserRegistration("bob", originalPasswordText, "Spongebob", "longPassword", None)
          val result = userProvider.registerUser(Json.toJson(registration)(Json.writes), sampleEpoch)

          result.failureValue shouldBe SecondFactorRequired("2FA enrollment is required")
        }
      }
    }
  }

  object TestSetup {
    val generator = new SecureSecretGenerator
    def apply(initialUsers: Map[user.DBUser, (user.UserPermissions, List[Collection])], reqUser: user.DBUser)(fn: (Users, UserManagement) => Unit): Unit = {
      import scala.concurrent.ExecutionContext.Implicits.global

      val dbAuthConfig = DatabaseAuthConfig(12, require2FA = false, "pfi")
      val hashing = new PasswordHashing
      val validator = new PasswordValidator(dbAuthConfig.minPasswordLength)
      val userManagement = TestUserManagement(initialUsers)

      val controllerComponents = stubControllerComponentsAsUser(reqUser.username, userManagement)
      val tfa = new TwoFactorAuth(require2fa = false, totp, userManagement)
      val userProvider = new DatabaseUserProvider(dbAuthConfig, hashing, userManagement, Totp.googleAuthenticatorInstance(), generator, validator, tfa)
      val controller = new Users(controllerComponents, userProvider)

      fn(controller, userManagement)
    }
  }
}
