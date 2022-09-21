package model.frontend.user

import play.api.libs.json.Json

case class UserRegistration(username: String, previousPassword: String, displayName: String, newPassword: String)

object UserRegistration {
  implicit val formats = Json.format[UserRegistration]
}
