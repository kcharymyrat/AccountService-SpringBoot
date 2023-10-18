package account.presentation

import account.businesslayer.*
import account.businesslayer.SecurityConfig
import account.persistence.AppUserRepository
import account.persistence.PaymentRepository
import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.annotation.AuthenticationPrincipal
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.*
import org.springframework.web.server.ResponseStatusException
import java.time.YearMonth
import java.time.format.DateTimeFormatter
import java.util.*
import javax.validation.constraints.NotBlank
import javax.validation.constraints.NotEmpty
import javax.validation.constraints.Pattern
import javax.validation.constraints.Size

val breachedPasswords = listOf("PasswordForJanuary", "PasswordForFebruary", "PasswordForMarch", "PasswordForApril",
    "PasswordForMay", "PasswordForJune", "PasswordForJuly", "PasswordForAugust",
    "PasswordForSeptember", "PasswordForOctober", "PasswordForNovember", "PasswordForDecember")

data class SignUpRequest(
    val name: String,
    val lastname: String,
    val email: String,
    val password: String,
    val roles: List<String>?
)

data class SignUpResponse(
    val id: Long,
    val name: String,
    val lastname: String,
    val email: String,
    val roles: MutableList<Role>
)

data class NewPasswordRequest(
    @field:NotEmpty
    @field:NotBlank
    @get:Size(min = 12)
    @JsonProperty(value = "new_password")
    val newPassword: String
)

data class NewPasswordResponse(val email: String, val status: String)

data class SinglePaymentResponse(val name: String, val lastname: String, val period: String, val salary: String)

data class PaymentRequest(val employee: String, val period: String, val salary: Long)

data class AppUserWithRoles(
    val id: Long?,
    val name: String,
    val lastname: String,
    val email: String,
    val roles: MutableList<Role>
)

const val strength = 13
val passwordEncoder = BCryptPasswordEncoder(strength)


@RestController
class DemoController(
    private val repository: AppUserRepository,
    private val paymentRepository: PaymentRepository,
)
{
    @PostMapping("/api/auth/signup")
    fun register(@RequestBody request: SignUpRequest): ResponseEntity<SignUpResponse>? {
        println("signUpRequest = $request")

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

            println("request.roles = ${request.roles}")
            println("user.id = ${user.id}")

            if (request.roles == null) {
                user.roles.add(Role.ROLE_USER)
            } else {
                request.roles.forEach {
                    when (it) {
                        "ROLE_USER" -> user.roles.add(Role.ROLE_USER)
                        "ROLE_ACCOUNTANT" -> user.roles.add(Role.ROLE_ACCOUNTANT)
                        "ROLE_ADMINISTRATOR" -> user.roles.add(Role.ROLE_ADMINISTRATOR)
                    }
                }
            }

            var newUser = repository.save(user)
            if (newUser.id == 1.toLong()) {
                newUser.roles.remove(Role.ROLE_USER)
                newUser.roles.add(Role.ROLE_ADMINISTRATOR)
            }
            newUser = repository.save(newUser)

            ResponseEntity.ok(
                newUser.id?.toLong()?.let {
                    SignUpResponse(
                        id = it,
                        name = newUser.name.toString(),
                        lastname = newUser.lastname.toString(),
                        email = newUser.email.toString(),
                        roles = newUser.roles
                    )
                }
            )
        } else {
            println("in else, request = $request")
            ResponseEntity.status(HttpStatus.BAD_REQUEST).build()
        }
    }

    @GetMapping("api/empl/payment")
    fun getEmployeePayments(
        @AuthenticationPrincipal details: UserDetails?,
        @RequestParam(required = false)
//        @Pattern(regexp = "^(0[1-9]|1[0-2])-(19|20)\\d{2}$", message = "Wrong date!")
        period: String?
    ): ResponseEntity<Any> {
        println()
        println("@GetMapping(\"api/empl/payment\")")
        println("userDetails = $details")

        if (details == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        val email = details.username
        val password = passwordEncoder.encode(details.password)

        val appUser = repository.findAppUserByEmail(details.username) ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        println("appUser.password = ${appUser.password}, password = $password")
        println("passwordEncoder.matches(password, user.password) = ${passwordEncoder.matches(password, appUser.password)}")
        if (password.trim().length < 12) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
        if (password.trim() in breachedPasswords) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()

        var emplPayments = paymentRepository.findPaymentByEmployeeIgnoreCase(details.username)
        if (period != null) {
            try {
                val formatter = DateTimeFormatter.ofPattern("MM-yyyy")
                val yearMonth = YearMonth.parse(period.trim(), formatter)
                emplPayments = emplPayments.filter { it.period == yearMonth }
            } catch (e:Exception) {
                throw PasswordsNotMatchException()
            }
        }
        println("emplPayments = $emplPayments")

        val listOfEmplPayments = mutableListOf<SinglePaymentResponse>()

        val formatter = DateTimeFormatter.ofPattern("MMMM-yyyy", Locale.ENGLISH)
        emplPayments.forEach {
            listOfEmplPayments.add(
                SinglePaymentResponse(
                    name = appUser.name.toString(),
                    lastname = appUser.lastname.toString(),
                    period = it.period.format(formatter),
                    salary = "${it.salary / 100} dollar(s) ${it.salary % 100} cent(s)",
                )
            )
        }
        return if (listOfEmplPayments.size == 1) ResponseEntity.ok(listOfEmplPayments[0])
        else ResponseEntity.ok(listOfEmplPayments.reversed())
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

    @PostMapping("api/acct/payments")
    fun makePayments(@RequestBody payments: List<PaymentRequest>): ResponseEntity<Any> {
        println("payments = $payments")

        for (payment in payments) {
            if (!canAddSinglePayment(payment, paymentRepository, repository)) throw PasswordsNotMatchException()
        }

        payments.forEach {
            savePaymentDAO(it, paymentRepository)
        }

        return ResponseEntity.ok(
            mapOf("status" to "Added successfully!")
        )
    }

    @PutMapping("api/acct/payments")
    fun updatePayment(@RequestBody payment: PaymentRequest): ResponseEntity<Any> {
        println("payment = $payment")
        return if (isDateAndSalaryValid(payment, paymentRepository)) {
            val formatter = DateTimeFormatter.ofPattern("MM-yyyy")
            val yearMonth = YearMonth.parse(payment.period.trim().toString(), formatter)
            val paymentDAO = paymentRepository.findPaymentByEmployeeIgnoreCaseAndPeriod(payment.employee, yearMonth) ?: throw PasswordsNotMatchException()
            paymentDAO.salary = payment.salary
            paymentRepository.save(paymentDAO)
            ResponseEntity.ok(
                mapOf("status" to "Updated successfully!")
            )
        } else {
            throw PasswordsNotMatchException()
        }
    }

    @GetMapping("/api/admin/user")
    fun getAllRoles(): ResponseEntity<MutableList<AppUserWithRoles>> {
        try {
            println()
            println("@GetMapping(\"/api/admin/user/\")")
            val response = mutableListOf<AppUserWithRoles>()
            val allUsers = repository.findAll()
            println("allUsers = $allUsers")
            for (user in allUsers) {
                response.add(
                    AppUserWithRoles(
                        id = user.id,
                        name = user.name.toString(),
                        lastname = user.lastname.toString(),
                        email = user.email.toString(),
                        roles = user.roles
                    )
                )
            }
            println("response = $response")
            return ResponseEntity.ok(response)
        } catch (e: Exception) {
            println("exception")
            throw ResponseStatusException(
                HttpStatus.FORBIDDEN, "Access Denied!"
            )
        }
    }

    @DeleteMapping("/api/admin/user/{email}")
    fun deleteUser(@PathVariable email: String): ResponseEntity<Map<String, String>> {
        println()
        println("@DeleteMapping(\"/api/admin/user/{email}\")")
        println("email = $email")
        val user = repository.findAppUserByEmail(email.lowercase().trim())
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User not found!")

        if (user.roles.contains(Role.ROLE_ADMINISTRATOR))
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Can't remove ADMINISTRATOR role!")

        repository.delete(user)
        return ResponseEntity.ok(mapOf("user" to email, "status" to "Deleted successfully!"))
    }

    @PutMapping("/api/admin/user/role")
    fun updateUserRoles(@RequestBody operation: RoleOperationDTO?): ResponseEntity<AppUser> {
        println()
        println("operation = $operation")
        if (operation == null) throw ResponseStatusException(
            HttpStatus.FORBIDDEN, "Access Denied!"
        )
        val user = repository.findAppUserByEmail(operation.email.lowercase().trim())
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User not found!")
        val appUserAdapter = AppUserAdapter(user)
        println("user.roles = ${user.roles}")

        val role: Role = checkRole(operation.role)
            ?: throw ResponseStatusException(
                HttpStatus.NOT_FOUND, "Role not found!"
            )

        if (operation.operation == "GRANT") {

            if (user.roles
                    .contains(Role.ROLE_ADMINISTRATOR) || role === Role.ROLE_ADMINISTRATOR
            ) throw ResponseStatusException(
                HttpStatus.BAD_REQUEST, "The user cannot combine administrative and business roles!"
            )

            appUserAdapter.grantAuthority(role)
            repository.save(user)
            println("granted roles = ${user.roles}")

        } else if (operation.operation == "REMOVE") {

            if (!user.roles.contains(role)) throw ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "The user does not have a role!"
            )
            if (role == Role.ROLE_ADMINISTRATOR) throw ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Can't remove ADMINISTRATOR role!"
            )
            if (user.roles.size == 1) throw ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "The user must have at least one role!"
            )

            appUserAdapter.removeAuthority(role)
            repository.save(user)
            println("removed roles = ${user.roles}")
        }

        println("user.roles = ${user.roles}")

        return ResponseEntity.ok(user)
    }


}



fun checkRole(role: String): Role? {
    for (r in Role.values()) {
        if (r.name == String.format("ROLE_%s", role)) {
            return r
        }
    }
    return null
}


fun savePaymentDAO(payment: PaymentRequest, paymentRepository: PaymentRepository) {
    val paymentDAO = Payment()
    paymentDAO.employee = payment.employee
    val formatter = DateTimeFormatter.ofPattern("MM-yyyy")
    val yearMonth = YearMonth.parse(payment.period.trim().toString(), formatter)
    paymentDAO.period = yearMonth
    paymentDAO.salary = payment.salary
    paymentRepository.save(paymentDAO)
}

fun canAddSinglePayment(payment: PaymentRequest, paymentRepository: PaymentRepository, repository: AppUserRepository): Boolean {
    // An employee must be among the users of our service;
    val appUser = payment.employee.let { repository.findAppUserByEmail(it) } ?: return false

    // Salary is calculated in cents and cannot be negative
    // The period for which the salary is paid must be unique for each employee (for POST)
    return if (isDateAndSalaryValid(payment, paymentRepository)){
        val formatter = DateTimeFormatter.ofPattern("MM-yyyy")
        val yearMonth = YearMonth.parse(payment.period.trim().toString(), formatter)
        val prevPayment = paymentRepository.findPaymentByEmployeeIgnoreCaseAndPeriod(payment.employee, yearMonth)
        prevPayment == null
    } else {
        false
    }
}


fun isDateAndSalaryValid(payment: PaymentRequest, paymentRepository: PaymentRepository): Boolean {
    // Salary is calculated in cents and cannot be negative
    try {
        val salary = payment.salary
        if (salary < 0) return false

        // The period for which the salary is paid must be unique for each employee (for POST)
        println("payment.period = ${payment.period}, ${payment.period.length}")
        val formatter = DateTimeFormatter.ofPattern("MM-yyyy")
        val yearMonth = YearMonth.parse(payment.period.trim().toString(), formatter)
        return true
    } catch (e:Exception) {
        return false
    }
}

fun isValidPassword(password: String): Boolean {
    // Verify that user passwords contain at least 12 characters;
    val trimmedPass = password.trim()
    return !(trimmedPass.length < 12 || trimmedPass in breachedPasswords)
}



/////////////////////////////////////////////////////////////////////////////////////////
//    @GetMapping("/api/empl/payment")
//    fun authenticate(@AuthenticationPrincipal details: UserDetails?): ResponseEntity<SignUpResponse>? {
//        if (details == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
//        val email = details.username
//        val password = passwordEncoder.encode(details.password)
//        val user = repository.findAppUserByEmail(email) ?: return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
//        println("user.password = ${user.password}, password = $password")
//        println("passwordEncoder.matches(password, user.password) = ${passwordEncoder.matches(password, user.password)}")
//        if (password.trim().length < 12) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
//        if (password.trim() in breachedPasswords) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
////        if (password != user.password) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
////        if (!passwordEncoder.matches(password, user?.password)) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build()
//        return ResponseEntity.ok(
//            user.id?.toLong()?.let {
//                SignUpResponse(
//                    id = it,
//                    name = user.name.toString(),
//                    lastname = user.lastname.toString(),
//                    email = user.email.toString()
//                )
//            }
//        )
//    }
