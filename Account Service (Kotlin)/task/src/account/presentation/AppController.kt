package account.presentation

import account.businesslayer.*
import account.businesslayer.SecurityConfig
import account.persistence.AppUserRepository
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.validation.constraints.NotBlank
import javax.validation.constraints.NotEmpty
import javax.validation.constraints.Size

val breachedPasswords = listOf("PasswordForJanuary", "PasswordForFebruary", "PasswordForMarch", "PasswordForApril",
    "PasswordForMay", "PasswordForJune", "PasswordForJuly", "PasswordForAugust",
    "PasswordForSeptember", "PasswordForOctober", "PasswordForNovember", "PasswordForDecember")

data class SignUpRequest(
    val name: String,
    val lastname: String,
    val email: String,
    val password: String,
)

data class SignUpResponse(
    val id: Long,
    val name: String,
    val lastname: String,
    val email: String,
)

data class NewPasswordRequest(
    @field:NotEmpty
    @field:NotBlank
    @get:Size(min = 12)
    @JsonProperty(value = "new_password")
    val newPassword: String
)

data class NewPasswordResponse(val email: String, val status: String)

const val strength = 13
val passwordEncoder = BCryptPasswordEncoder(strength)


@RestController
class DemoController(
    private val repository: AppUserRepository
)
{
    @PostMapping("/api/auth/signup")
    fun register(@RequestBody request: SignUpRequest): ResponseEntity<SignUpResponse>? {

        return if (request.email.endsWith("@acme.com") && request.name.isNotBlank() && request.lastname.isNotBlank() && request.password.isNotBlank()) {
            println("\nin /register \n")
            val user = AppUser()
            user.name = request.name
            user.lastname = request.lastname
            user.email = request.email.lowercase()
            if (repository.findAll().any { user.email.equals(it.email, true) }) {
                throw UserExistsException()
            }
            if (request.password.trim().length < 12) throw ShortPasswordException()
            if (request.password.trim() in breachedPasswords) throw BreachedPasswordException()
            user.password = passwordEncoder.encode(request.password.trim())
            user.authority = Role.USER.toString()
            val newUser = repository.save(user)


            ResponseEntity.ok(
                newUser.id?.toLong()?.let {
                    SignUpResponse(
                        id = it,
                        name = newUser.name.toString(),
                        lastname = newUser.lastname.toString(),
                        email = newUser.email.toString()
                    )
                }
            )
        } else {
            println("in else, request = $request")
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
    }

    @PostMapping("api/auth/changepass")
    fun changePassword(@AuthenticationPrincipal details: UserDetails?, @RequestBody request: NewPasswordRequest): ResponseEntity<NewPasswordResponse> {
        if (details == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        val email = details.username
        val oldPassword = details.password
        val appUser = repository.findAppUserByEmail(email) ?: throw UserNotFoundException()
        if (oldPassword != appUser.password) throw UserNotFoundException()

        val newPassword = request.newPassword
        println("email = $email")
        println("oldPassword = $oldPassword, newPassword = $newPassword")
        println("passwordEncoder.matches(newPassword, oldPassword) = ${passwordEncoder.matches(newPassword, appUser.password)}")
        if (newPassword.trim().length < 12) throw ShortPasswordException()
        if (newPassword.trim() in breachedPasswords) throw BreachedPasswordException()
        if (passwordEncoder.matches(newPassword, appUser.password)) throw PasswordsNotMatchException()

        appUser.password = passwordEncoder.encode(request.newPassword.trim())
        repository.save(appUser)
        return ResponseEntity.ok(
            NewPasswordResponse(details.username, "The password has been updated successfully")
        )
    }

    @GetMapping("/api/empl/payment")
    fun authenticate(@AuthenticationPrincipal details: UserDetails?): ResponseEntity<SignUpResponse>? {
        if (details == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        val email = details.username
        val password = passwordEncoder.encode(details.password)
        val user = repository.findAppUserByEmail(email) ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        println("user.password = ${user.password}, password = $password")
        println("passwordEncoder.matches(password, user.password) = ${passwordEncoder.matches(password, user.password)}")
        if (password.trim().length < 12) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        if (password.trim() in breachedPasswords) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
//        if (password != user.password) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
//        if (!passwordEncoder.matches(password, user?.password)) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        return ResponseEntity.ok(
            user.id?.toLong()?.let {
                SignUpResponse(
                    id = it,
                    name = user.name.toString(),
                    lastname = user.lastname.toString(),
                    email = user.email.toString()
                )
            }
        )
    }

    @GetMapping("/test")
    fun test(): String {
        return "Access to '/test' granted"
    }

    @GetMapping("/username")
    fun username(@AuthenticationPrincipal details: UserDetails) {
        println(details.username)
    }

    @GetMapping("/details")
    fun details(@AuthenticationPrincipal details: UserDetails)  {
        println("Username: " + details.username)
        println("User has authorities/roles: " + details.authorities)
    }

}

fun isValidPassword(password: String): Boolean {
    // Verify that user passwords contain at least 12 characters;
    val trimmedPass = password.trim()
    return !(trimmedPass.length < 12 || trimmedPass in breachedPasswords)
}

