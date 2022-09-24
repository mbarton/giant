package utils.auth.providers

import model.frontend.user.{PartialUser, TfaRegistration, TfaRegistrationParameters, TfaChallengeParameters}
import play.api.libs.json._
import play.api.mvc.{AnyContent, Request}
import services.AuthProviderConfig
import utils.Epoch
import utils.attempt._

/**
  * A trait that authenticates a user
  */
trait UserProvider {
  /** The configuration for this user provider **/
  def config: AuthProviderConfig
  /** the configuration that is shipped to the UI for enhancements like client side minimum password length checks etc. **/
  def clientConfig: Map[String, JsValue]
  /** authenticate a user based on the HTTP request and the current time (for any 2FA calculations) **/
  def authenticate(request: Request[AnyContent], time: Epoch): Attempt[PartialUser]
  /** create an all powerful initial user **/
  def genesisUser(request: JsValue, time: Epoch): Attempt[PartialUser]
  /** create a new user account */
  def createUser(username: String, request: JsValue): Attempt[PartialUser]
  /** register a user (set up password/2FA) that has already been created by an admin **/
  def registerUser(request: JsValue, time: Epoch): Attempt[Unit]
  /** delete and disable a user account **/
  def removeUser(username: String): Attempt[Unit]
  /** update the password of a user **/
  def updatePassword(username: String, newPassword: String): Attempt[Unit]
  /** generate brand new 2FA secrets and challenges ready for a user to add their device * */
  def get2faRegistrationParameters(request: Request[AnyContent], time: Epoch, instance: String): Attempt[TfaRegistrationParameters]
  /** get any configuration required to support 2fa (eg webauthn credential ids and challenge) */
  def get2faChallengeParameters(request: Request[AnyContent], time: Epoch): Attempt[TfaChallengeParameters]
  /** register a new 2fa method */
  def register2faMethod(request: Request[AnyContent], time: Epoch): Attempt[TfaChallengeParameters]
}