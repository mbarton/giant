package services.users

import model.Uri
import model.manifest.Collection
import model.user._
import utils.attempt.Attempt

import scala.concurrent.ExecutionContext

trait UserManagement {
  def listUsers(): Attempt[List[(DBUser, List[Collection])]]
  def listUsersWithPermission(permission: UserPermission): Attempt[List[DBUser]]
  def getPermissions(username: String): Attempt[UserPermissions]
  def createUser(user: DBUser, permissions: UserPermissions): Attempt[DBUser]
  def registerUser(username: String, displayName: String, password: Option[BCryptPassword], tfa: Option[DBUser2fa]): Attempt[DBUser]
  def updateUserDisplayName(username: String, displayName: String): Attempt[DBUser]
  def updateUserPassword(username: String, password: BCryptPassword): Attempt[DBUser]
  def getUser(username: String): Attempt[DBUser]
  def removeUser(username: String): Attempt[Unit]
  def updateInvalidatedTime(username: String, invalidatedTime: Long): Attempt[DBUser]
  def getAllCollectionUrisAndUsernames(): Attempt[Map[String, Set[String]]]
  def getUsersForCollection(collectionUri: String): Attempt[Set[String]]
  def getVisibleCollectionUrisForUser(user: String): Attempt[Set[String]]
  def addUserCollection(user: String, collection: String): Attempt[Unit]
  def removeUserCollection(user: String, collection: String): Attempt[Unit]
  def setPermissions(user: String, permissions: UserPermissions): Attempt[Unit]
  def setUser2fa(user: String, tfa: DBUser2fa): Attempt[Unit]
  def getGenesisRegistration2fa(): Attempt[DBUser2fa]
  def setGenesisRegistration2fa(tfa: DBUser2fa): Attempt[Unit]
  def canSeeCollection(user: String, collection: Uri)(implicit ec: ExecutionContext): Attempt[Boolean] =
    getVisibleCollectionUrisForUser(user).map(_.contains(collection.value))

  def hasPermission(user: String, permission: UserPermission)(implicit ec: ExecutionContext): Attempt[Boolean] =
    getPermissions(user).map(_.hasPermission(permission))
}
