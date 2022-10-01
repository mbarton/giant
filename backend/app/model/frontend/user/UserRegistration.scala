package model.frontend.user

import play.api.libs.json.Json

case class UserRegistration(username: String, previousPassword: String, displayName: String, newPassword: String, tfa: Option[TfaRegistration])

object UserRegistration {
  implicit val format = Json.format[UserRegistration]
}
