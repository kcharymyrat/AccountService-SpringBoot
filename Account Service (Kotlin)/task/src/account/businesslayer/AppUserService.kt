package account.businesslayer

import account.persistence.AppUserRepository
import account.persistence.BreachedPasswordRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.web.server.ResponseStatusException

@Service
class AppUserService : UserDetailsService {

    @Autowired
    private lateinit var userRepository: AppUserRepository

    @Autowired
    private lateinit var breachedPasswordRepository: BreachedPasswordRepository

    @Autowired
    private lateinit var passwordEncoder: PasswordEncoder

    @Autowired
    private lateinit var auditService: AuditService

    private val MAX_FAILED_ATTEMPTS = 5

    fun findByEmail(email: String): AppUser {
        return userRepository.findUserByEmailIgnoreCase(email.toLowerCase())
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User not found!")
    }

    fun registerNewUser(user: AppUser, path: String): AppUser {
        user.email = user.email.toLowerCase()
        user.setIsAccountNonLocked(true)
        checkValidPassword(user.password)

        if (userRepository.findUserByEmailIgnoreCase(user.email) == null) {

            if (userRepository.count() == 0L) {
                user.grantAuthority(Role.ROLE_ADMINISTRATOR)
            } else user.grantAuthority(Role.ROLE_USER)

            user.password = passwordEncoder.encode(user.password)
            auditService.logEvent(Action.CREATE_USER, null, user.email, path);
            userRepository.save(user)

        } else throw ResponseStatusException(HttpStatus.BAD_REQUEST, "User exist!")

        return user
    }

    fun getAllRoles(): ResponseEntity<MutableList<AppUser>> {
        return ResponseEntity.ok<MutableList<AppUser>>(userRepository.findAll() as MutableList<AppUser>)
    }

    fun deleteUser(email: String, path: String, adminEmail: String): ResponseEntity<Map<String, String>> {
        val user: AppUser = userRepository.findUserByEmailIgnoreCase(email)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User not found!")

        if (user.roles.contains(Role.ROLE_ADMINISTRATOR))
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Can't remove ADMINISTRATOR role!")

        auditService.logEvent(Action.DELETE_USER, adminEmail, user.email, path);
        userRepository.delete(user)

        return ResponseEntity.ok(mapOf("user" to email, "status" to "Deleted successfully!"))
    }

    fun changePassword(newPassword: String, authUser: AppUser, path: String): ResponseEntity<Map<String, String>> {
        checkValidPassword(newPassword)
        checkDifferencePasswords(newPassword, authUser.password)

        val tmpUser: AppUser? = userRepository.findUserByEmailIgnoreCase(authUser.email)

        tmpUser?.password = passwordEncoder.encode(newPassword)
        auditService.logEvent(Action.CHANGE_PASSWORD, tmpUser?.email, tmpUser?.email, path);
        userRepository.save(tmpUser!!)

        return ResponseEntity(
            mapOf("email" to authUser.email, "status" to "The password has been updated successfully"),
            HttpStatus.OK
        )
    }

    fun updateRole(operation: RoleOperationDTO, path: String, adminEmail: String): ResponseEntity<AppUser> {
        val user: AppUser = userRepository.findUserByEmailIgnoreCase(operation.email)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User not found!")

        val role: Role = checkRole(operation.role)

        when (operation.operation) {
            "GRANT" -> {
                if (user.roles
                        .contains(Role.ROLE_ADMINISTRATOR) || role === Role.ROLE_ADMINISTRATOR
                ) throw ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "The user cannot combine administrative and business roles!"
                )

                user.grantAuthority(role)

                val message = "Grant role ${role.name.split("_")[1]} to ${user.email}"

                auditService.logEvent(Action.GRANT_ROLE, adminEmail, message, path)
            }

            "REMOVE" -> {
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

                user.removeAuthority(role)

                val message = "Remove role ${role.name.split("_")[1]} from ${user.email}"

                auditService.logEvent(Action.REMOVE_ROLE, adminEmail, message, path)
            }
        }

        return ResponseEntity.ok(userRepository.save(user))

    }

    fun userAccessOperation(
        operation: UserAccessDTO,
        adminEmail: String,
        requestPath: String
    ): ResponseEntity<UserAccessDTO> {

        val user: AppUser = loadUserByUsername(operation.user)

        if (user.roles.contains(Role.ROLE_ADMINISTRATOR)) throw ResponseStatusException(
            HttpStatus.BAD_REQUEST,
            "Can't lock the ADMINISTRATOR!"
        )

        user.setIsAccountNonLocked(Operation.LOCK !== operation.operation)

        if (Operation.LOCK === operation.operation) {

            auditService.logEvent(
                Action.LOCK_USER,
                user.email,
                "Lock user ${user.email}",
                requestPath
            )

            operation.status = "User ${user.email} locked!"

        } else {

            user.failedAttempts = 0
            operation.status = "User ${user.email} unlocked!"

            auditService.logEvent(
                Action.UNLOCK_USER,
                adminEmail,
                "Unlock user ${user.email}",
                requestPath
            )

        }

        userRepository.save(user)

        return ResponseEntity.ok<UserAccessDTO>(operation)
    }

    override fun loadUserByUsername(email: String): AppUser {
        return userRepository.findUserByEmailIgnoreCase(email) ?: throw UsernameNotFoundException("$email not found!")
    }

    private fun checkValidPassword(password: String?) {
        if (password == null || password.length < 12) {
            throw PasswordTooShortException(Message.SIGNUP)
        }

        if (breachedPasswordRepository.existsBreachedPasswordsByPassword(password)) {
            throw BreachedPasswordException()
        }
    }

    private fun checkDifferencePasswords(newPassword: String, oldPassword: String) {
        if (passwordEncoder.matches(newPassword, oldPassword)) {
            throw RepetitivePasswordException()
        }
    }

    private fun checkRole(role: String): Role {
        for (r in Role.values()) {
            if (r.name == String.format("ROLE_%s", role)) {
                return r
            }
        }

        throw RoleNotFoundException()
    }

    fun increaseFailedAttempts(user: AppUser, path: String) {
        user.failedAttempts = user.failedAttempts + 1

        if (user.failedAttempts > MAX_FAILED_ATTEMPTS) lockUser(user, path)

        userRepository.save(user)
    }

    private fun lockUser(user: AppUser, path: String) {
        user.setIsAccountNonLocked(false)
        auditService.logEvent(Action.BRUTE_FORCE, user.email, path, path)

        auditService.logEvent(
            Action.LOCK_USER,
            user.email,
            "Lock user ${user.email}",
            path
        )
    }

}