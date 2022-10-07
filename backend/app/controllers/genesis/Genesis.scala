package controllers.genesis

import model.user.DBUser2fa
import play.api.libs.json.{JsBoolean, JsString, Json}
import play.api.mvc.ControllerComponents
import services.users.UserManagement
import utils.attempt._
import utils.auth.providers.UserProvider
import utils.auth.totp.{SecureSecretGenerator, Totp}
import utils.controller.NoAuthApiController
import utils.{Epoch, Logging}

import scala.util.Success

class Genesis(override val controllerComponents: ControllerComponents, userProvider: UserProvider, users: UserManagement, flowEnabled: Boolean)
  extends NoAuthApiController with Logging {

  private var setupComplete: Attempt[Boolean] = Attempt.Right(false)

  private def checkSetupComplete() = {
    if (flowEnabled) {
      val setupCompleteAttempt = users.listUsers().map { _.nonEmpty }
      setupCompleteAttempt.asFuture.onComplete{
        case Success(Right(setup)) => logger.info(s"Result from user db attempt: $setup")
        case Success(Left(failure)) => logger.error(s"Failed to get setup state from DB: $failure")
        case util.Failure(t) => logger.error(s"Failed to get setup state from DB", t)
      }
      setupCompleteAttempt
    } else {
      logger.info("Setting setupComplete to true as genesis user creation flow is disabled")
      Attempt.Right(true)
    }
  }

  private def getSetupComplete: Attempt[Boolean] = {
    if (setupComplete.value.contains(Right(false))) {
      // not yet initialised
      setupComplete = checkSetupComplete()
    }
    setupComplete
  }

  def checkSetup = ApiAction.attempt {
    getSetupComplete.flatMap {
      case true =>
        Attempt.Right(
          Ok(Json.toJson(Json.obj("setupComplete" -> true)))
        )

      case false =>
        userProvider.genesisUserConfig().map { genesisConfig =>
          Ok(Json.toJson(
            Map("setupComplete" -> JsBoolean(false)) ++ genesisConfig
          ))
        }
    }
  }

  def doSetup() = ApiAction.attempt(parse.json) { request =>
    val time = Epoch.now
    if (flowEnabled) {
      for {
        _ <- getSetupComplete.flatMap[Unit] { complete =>
          if (complete)
            Attempt.Left(AlreadySetupFailure("Setup already complete"))
          else
            Attempt.Right(())
        }
        created <- userProvider.genesisUser(request.body, time)
      } yield {
        Ok(Json.toJson(created))
      }
    } else {
      Attempt.Right(Forbidden("Genesis user flow not enabled"))
    }
  }
}
