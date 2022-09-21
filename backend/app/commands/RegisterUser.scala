package commands

import model.frontend.user.{TfaChallengeResponse, UserRegistration}
import services.users.UserManagement
import utils.{Epoch, Logging}
import utils.attempt.Attempt
import utils.auth.{PasswordHashing, PasswordValidator, RequireNotRegistered, TwoFactorAuth}

import scala.concurrent.ExecutionContext


case class RegisterUser(users: UserManagement,
                        crypto: PasswordHashing,
                        passwordValidator: PasswordValidator,
                        userData: UserRegistration,
                        tfaChallengeResponse: Option[TfaChallengeResponse],
                        tfa: TwoFactorAuth,
                        time: Epoch)
                       (implicit ec: ExecutionContext) extends AttemptCommand[Unit] with Logging {
  def process(): Attempt[Unit] = {
    logger.info(s"Attempt to register ${userData.username}")
    for {
      _ <- crypto.verifyUser(users.getUser(userData.username), userData.previousPassword, Some(RequireNotRegistered))
      _ <- passwordValidator.validate(userData.newPassword)
      newHash <- crypto.hash(userData.newPassword)
      user2fa <- users.getUser2fa(userData.username)
      _ <- tfa.check2fa(user2fa, tfaChallengeResponse, time)
      _ <- users.registerUser(userData.username, userData.displayName, Some(newHash))
    } yield {
      logger.info(s"Registered ${userData.username}")
      ()
    }
  }
}
