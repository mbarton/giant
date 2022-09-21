package test

import model.manifest.Collection
import model.user._
import model.{Uri, user}
import services.users.UserManagement
import utils.attempt._

import scala.concurrent.ExecutionContext.Implicits.global

object TestUserManagement {
  case class TestUserRegistration(dbUser: DBUser, permissions: UserPermissions, collections: List[Collection], tfa: DBUser2fa)
  type Storage = Map[String, TestUserRegistration]

  def apply(initialUsers: List[user.DBUser]): TestUserManagement = {
    val withPermissions: TestUserManagement.Storage = initialUsers.map(user =>
      user.username -> TestUserRegistration(user, UserPermissions.default, List.empty, DBUser2fa.empty)(scala.collection.breakOut)

    new TestUserManagement(withPermissions)
  }

  def apply(initialUsers: Map[user.DBUser, (user.UserPermissions, List[Collection])]): TestUserManagement = {
    new TestUserManagement(initialUsers.map { case (user, (perms, colls)) => user.username -> TestUserRegistration(user, perms, colls, DBUser2fa.empty) })
  }
}

class TestUserManagement(initialUsers: TestUserManagement.Storage) extends UserManagement {
  import TestUserManagement.TestUserRegistration

  private var users: TestUserManagement.Storage = initialUsers

  def getAllUsers: List[DBUser] = users.values.toList.map(_.dbUser)

  override def getUser(username: String): Attempt[DBUser] = {
    users.get(username).toAttempt(Attempt.Left(UserDoesNotExistFailure(username))).map(_.dbUser)
  }

  override def listUsers(): Attempt[List[(DBUser, List[Collection])]] = Attempt.Right {
    users.values.toList
      .map { case TestUserRegistration(dbUser, _, collections, _) => dbUser -> collections }
      .sortBy { case (dbUser, _) => dbUser.username }
  }

  def listUsersWithPermission(permission: UserPermission): Attempt[List[DBUser]] = Attempt.Right {
    users.values.collect { case TestUserRegistration(dbUser, permissions, _, _) if permissions.hasPermission(permission) => dbUser }
  }

  override def getPermissions(username: String): Attempt[UserPermissions] = {
    users.get(username).toAttempt(Attempt.Left(UserDoesNotExistFailure(username))).map(_.permissions)
  }

  override def removeUser(username: String): Attempt[Unit] = {
    users = users - username
    Attempt.Right(())
  }

  override def createUser(u: user.DBUser, p: user.UserPermissions): Attempt[DBUser] = {
    users = users + (u.username -> TestUserRegistration(u, p, List.empty, DBUser2fa.empty))
    Attempt.Right(u)
  }

  override def updateUserPassword(username: String, password: BCryptPassword): Attempt[DBUser] =
    updateDbUserField(username, _.copy(password = Some(password)))


  override def updateUserDisplayName(username: String, displayName: String): Attempt[DBUser] =
    updateDbUserField(username, _.copy(displayName = Some(displayName)))

  override def updateInvalidatedTime(username: String, invalidatedTime: Long): Attempt[DBUser] =
    updateDbUserField(username, _.copy(invalidationTime = Some(invalidatedTime)))

  override def addUserCollection(username: String, collection: String): Attempt[Unit] = {
    updateField(username, r => r.copy(collections = r.collections :+ Collection(Uri(collection), collection, List.empty, None))).map(_ => ())
  }

  def getAllCollectionUrisAndUsernames(): Attempt[Map[String, Set[String]]] = Attempt.Right {
    users.foldLeft(Map.empty[String, Set[String]]) { case (acc, (username, TestUserRegistration(_, _, collections, _))) =>
      collections.foldLeft(acc) { (acc, collection) =>
        val before = acc.getOrElse(collection.uri.value, Set.empty)
        val after = before + username

        acc + (collection.uri.value  -> after)
      }
    }
  }

  override def getUsersForCollection(collectionUri: String): Attempt[Set[String]] = Attempt.Right {
    users.collect {
      case (username, TestUserRegistration(_, _, collections, _)) if collections.exists(_.uri.value == collectionUri) => username
    }.toSet
  }

  override def getVisibleCollectionUrisForUser(username: String): Attempt[Set[String]] = {
    users.get(username).toAttempt(Attempt.Left(UserDoesNotExistFailure(username))).map { case TestUserRegistration(_, _, colls, _) =>
      colls.map(_.uri.value).toSet
    }
  }

  override def removeUserCollection(username: String, collection: String): Attempt[Unit] =
    updateField(username, r => r.copy(collections = r.collections.filterNot(_.uri.value == collection))).map(_ => ())

  override def registerUser(username: String, displayName: String, password: Option[BCryptPassword]): Attempt[DBUser] =
    updateField(username, r => r.copy(
      dbUser = r.dbUser.copy(
        password = password,
        displayName = Some(displayName),
        registered = true
      )
    )).map(r => r.dbUser)

  override def setPermissions(username: String, permissions: UserPermissions): Attempt[Unit] =
    updateField(username, r => r.copy(permissions = permissions)).map(_ => ())

  override def getUser2fa(username: String): Attempt[DBUser2fa] =
    users.get(username).toAttempt(Attempt.Left(UserDoesNotExistFailure(username))).map(_.tfa)

  override def setUser2fa(username: String, tfa: DBUser2fa): Attempt[Unit] =
    updateField(username, r => r.copy(tfa = tfa)).map(_ => ())

  private def updateField(username: String, f: TestUserRegistration => TestUserRegistration): Attempt[TestUserRegistration] = {
    val maybeUpdatedUser = users
      .get(username)
      .map {r => username -> f(r) }

    users = users ++ maybeUpdatedUser
    maybeUpdatedUser.fold[Attempt[TestUserRegistration]]
      { Attempt.Left(UserDoesNotExistFailure(username)) }
      { case (_, user) => Attempt.Right(user) }
  }

  private def updateDbUserField(username: String, f: DBUser => DBUser): Attempt[DBUser] = {
    updateField(username, r => r.copy(dbUser = f(r.dbUser))).map(_.dbUser)
  }
}
