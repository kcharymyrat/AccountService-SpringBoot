package account.businesslayer

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ResponseStatus

@ResponseStatus(code = HttpStatus.BAD_REQUEST, reason = "User exist!")
class UserExistsException : RuntimeException()

@ResponseStatus(code = HttpStatus.UNAUTHORIZED, reason = "User not found!")
class UserNotFoundException : RuntimeException()