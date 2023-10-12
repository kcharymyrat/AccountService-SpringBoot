package account

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

data class SignUpRequest(
        val name: String,
        val lastname: String,
        val email: String,
        val password: String,
)

data class SignUpResponse(
        val name: String,
        val lastname: String,
        val email: String,
)

@RestController
@RequestMapping("/api/auth")
class SignUpController {

    @PostMapping("/signup")
    fun signUp(@RequestBody request: SignUpRequest): ResponseEntity<SignUpResponse> {
        println("In SignUpController")
        return if (request.email.endsWith("@acme.com") && request.name.isNotBlank() && request.lastname.isNotBlank() && request.password.isNotBlank()) {
            println("in if, request = $request")
            ResponseEntity.ok(
                    SignUpResponse(
                            name = request.name,
                            lastname = request.lastname,
                            email = request.email
                    )
            )
        } else {
            println("in else, request = $request")
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
    }
}