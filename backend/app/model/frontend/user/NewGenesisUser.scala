package model.frontend.user

import play.api.libs.json.Json

case class NewGenesisUser(username: String, displayName: String, password: String)

object NewGenesisUser {
  implicit val genesisUserFormat = Json.format[NewGenesisUser]
}
