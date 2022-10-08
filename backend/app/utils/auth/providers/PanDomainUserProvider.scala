package utils.auth.providers

import com.gu.pandomainauth.model._
import com.gu.pandomainauth.{PanDomain, PublicKey}
import model.frontend.user.PartialUser
import model.user.{DBUser, DBUser2fa, UserPermissions}
import model.frontend.user.{TfaChallengeParameters, TfaRegistration, TfaRegistrationParameters}
import play.api.libs.json.{JsString, JsValue}
import play.api.mvc.{AnyContent, Request}
import services.users.UserManagement
import services.{MetricsService, PandaAuthConfig}
import utils.attempt.AttemptAwait._
import utils.attempt._
import utils.{Epoch, Logging}

import scala.concurrent.ExecutionContext
import scala.concurrent.duration._

/**
  * A UserAuthenticator implementation that authenticates a valid user based on the presence of a pan-domain cookie
  */
class PanDomainUserProvider(val config: PandaAuthConfig, currentPublicKey: () => Option[PublicKey], users: UserManagement, metricsService: MetricsService)(implicit ec: ExecutionContext)
  extends UserProvider with Logging {

  /** The client needs to know where to redirect the user so they can pick up a pan domain cookie **/
  override def clientConfig: Map[String, JsValue] = Map(
    "loginUrl" -> JsString(config.loginUrl)
  )

  override def genesisUserConfig(): Attempt[Map[String, JsValue]] = Attempt.Right(Map.empty)

  override def authenticate(request: Request[AnyContent], time: Epoch): Attempt[PartialUser] = {

    def validateUser(user: AuthenticatedUser): Boolean = {
      val passesMultifactor = if (config.require2FA) user.multiFactor else true
      val dbUser = users.getUser(user.user.email).awaitEither(10.seconds)
      dbUser.isRight && passesMultifactor
    }

    val maybeCookie = request.cookies.get(config.cookieName)

    (currentPublicKey(), maybeCookie) match {
      case (Some(publicKey), Some(cookieData)) =>
        val status = PanDomain.authStatus(cookieData.value, publicKey, validateUser, 0L, "giant", false)
        status match {
          case Authenticated(authedUser) =>
            for {
              user <- users.getUser(authedUser.user.email)
              displayName = s"${authedUser.user.firstName} ${authedUser.user.lastName}"
              _ <- if (user.registered)
                Attempt.Right(user)
              else {
                users.registerUser(user.username, displayName, None, None)
              }
            } yield {
              metricsService.recordUsageEvent(user.username)
              PartialUser(user.username, user.displayName.getOrElse(displayName))
            }
          case NotAuthorized(authedUser) => Attempt.Left(PanDomainCookieInvalid(s"User ${authedUser.user.email} is not authorised to use this system.", reportAsFailure = true))
          case InvalidCookie(exception) => Attempt.Left(PanDomainCookieInvalid(s"Pan domain cookie invalid: ${exception.getMessage}", reportAsFailure = true))
          case Expired(authedUser) => Attempt.Left(PanDomainCookieInvalid(s"User ${authedUser.user.email} panda cookie has expired.", reportAsFailure = false))
          case other =>
            logger.warn(s"Pan domain auth failure: $other")
            Attempt.Left(AuthenticationFailure(s"Pan domain auth failed: $other", reportAsFailure = true))
        }
      case (None, _) => Attempt.Left(AuthenticationFailure("Pan domain library not initialised - no public key available", reportAsFailure = true))
      case (_, None) => Attempt.Left(PanDomainCookieInvalid(s"No pan domain cookie available in request with name ${config.cookieName}", reportAsFailure = false))
    }
  }

  /** create an all powerful initial user **/
  override def genesisUser(request: JsValue, time: Epoch): Attempt[PartialUser] = {
    for {
      email <- (request \ "username").validate[String].toAttempt
      createdUser <- users.createUser(dbUser(email), UserPermissions.bigBoss)
    } yield createdUser.toPartial
  }

  /** create a new user account */
  override def createUser(username: String, request: JsValue): Attempt[PartialUser] = {
    for {
      // we mark this user as not registered so we can cache the display name when we see them
      createdUser <- users.createUser(dbUser(username), UserPermissions.default)
    } yield createdUser.toPartial
  }

  /** delete and disable a user account **/
  override def removeUser(username: String): Attempt[Unit] = {
    users.removeUser(username)
  }

  /** None of these make sense for a pan domain authed user so we return a failure **/
  override def updatePassword(username: String, newPassword: String): Attempt[Unit] = unsupportedOperation
  override def get2faRegistrationParameters(request: Request[AnyContent], time: Epoch): Attempt[TfaRegistrationParameters] = unsupportedOperation
  override def register2faMethod(username: String, registration: TfaRegistration, time: Epoch): Attempt[Unit] = unsupportedOperation
  override def registerUser(userData: JsValue, time: Epoch): Attempt[Unit] = unsupportedOperation

  def unsupportedOperation[T] = Attempt.Left[T](UnsupportedOperationFailure("This authentication provider is federated and doesn't support this operation."))

  private def dbUser(username: String): DBUser = DBUser(
    username = username,
    // filled in at registration
    displayName = None,
    // no password, auth is done by panda cookie
    password = None,
    invalidationTime = None,
    registered = false,
    // tfa fully handled by the panda OAuth provider for now. We could require separate tfa for Giant in the future
    tfa = DBUser2fa.empty
  )
}
