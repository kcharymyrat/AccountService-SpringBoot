package account.presentation

import account.businesslayer.AppUser
import account.businesslayer.AppUserAdapter
import account.businesslayer.Role
import account.businesslayer.UserExistsException
import account.persistence.AppUserRepository
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

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


@RestController
class DemoController(
    private val repository: AppUserRepository,
    private val passwordEncoder: PasswordEncoder
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
            user.authority = Role.USER.toString()
            user.password = passwordEncoder.encode(request.password)
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

    @GetMapping("/api/empl/payment")
    fun authenticate(@AuthenticationPrincipal details: UserDetails): ResponseEntity<SignUpResponse>? {
        val email = details.username
        val user = repository.findAppUserByEmail(email)
        return if (user != null) {
            ResponseEntity.ok(
                user.id?.toLong()?.let {
                    SignUpResponse(
                        id = it,
                        name = user.name.toString(),
                        lastname = user.lastname.toString(),
                        email = user.email.toString()
                    )
                }
            )
        } else {
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
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

