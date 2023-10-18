package account.businesslayer

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "User exist!")
class UserExistsException : RuntimeException()

@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "User not found!")
class UserNotFoundException : RuntimeException()

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "Password length must be 12 chars minimum!")
class ShortPasswordException : RuntimeException()

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "The password is in the hacker's database!")
class BreachedPasswordException : RuntimeException()

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "The passwords must be different!")
class PasswordsNotMatchException : RuntimeException()

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "The role was not found!")
class RoleNotFoundException : RuntimeException()