package controllers.api

import akka.stream.Materializer
import akka.stream.testkit.NoMaterializer
import model.user.{NewUser, UserPermissions}
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
import play.api.libs.json.{JsArray, JsObject, Json}
import play.api.mvc.{Action, AnyContentAsEmpty, Request, Results}
import play.api.test.FakeRequest
import play.api.test.Helpers._
import services.users.UserManagement
import test.integration.Helpers.stubControllerComponentsAsUser
import test.{AttemptValues, TestUserManagement, TestUserRegistration}

class UsersTest extends AnyFreeSpec with Matchers with Results with ScalaFutures with AttemptValues {
  import test.TestUserManagement._

  import scala.concurrent.ExecutionContext.Implicits.global
  implicit val mat: Materializer = NoMaterializer

  val admin = registeredUserNo2fa("admin").copy(permissions = UserPermissions.bigBoss)
  val punter = registeredUserNo2fa("punter")

  "UsersController" - {
    "list partial user information to punters" in {
      TestSetup(punter) { (controller, _) =>
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
      TestSetup(admin) { (controller, _) =>
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
      TestSetup(admin) { (controller, _) =>
        val result = controller.getMyPermissions.apply(FakeRequest())
        val json = contentAsJson(result)

        json.as[UserPermissions] should be(UserPermissions.bigBoss)
      }

      TestSetup(punter) { (controller, _) =>
        val result = controller.getMyPermissions.apply(FakeRequest())
        val json = contentAsJson(result)

        json.as[UserPermissions] should be(UserPermissions.default)
      }
    }

    "disallow operations without permission" in {
      TestSetup(punter) { (controller, _) =>
        def disallow[T](action: Action[T], body: T) = {
          val req: Request[T] = FakeRequest().withBody(body)
          val resp = action.apply(req)

          status(resp) should be(403)
        }

        disallow(controller.createUser("test"), Json.toJson(NewUser("test", "biglongpassword1234")))
        disallow(controller.removeUser(admin.username), AnyContentAsEmpty)

        disallow(controller.updateUserFullname(punter.username), Json.parse("""{"displayName": "test"}"""))
        disallow(controller.updateUserPassword(punter.username), Json.parse("""{"password": "biglongpassword1234"}"""))
      }
    }

    "create user that is flagged as not registered" in {
      TestSetup(admin) { (controller, db) =>
        val req = FakeRequest().withBody(Json.toJson(NewUser("test", "biglongpassword1234")))

        status(controller.createUser("test").apply(req)) should be(200)

        val users = db.listUsers().asFuture.futureValue.toOption.get
        users.find(_._1.username == "test").map(_._1.registered) should contain(false)
      }
    }
  }

  object TestSetup {
    def apply(reqUser: TestUserRegistration)(fn: (Users, UserManagement) => Unit): Unit = {
      val (userProvider, userManagement) = TestUserManagement.makeUserProvider(require2fa = false, admin, punter)

      val controllerComponents = stubControllerComponentsAsUser(reqUser.username, userManagement)
      val controller = new Users(controllerComponents, userProvider)

      fn(controller, userManagement)
    }
  }
}
