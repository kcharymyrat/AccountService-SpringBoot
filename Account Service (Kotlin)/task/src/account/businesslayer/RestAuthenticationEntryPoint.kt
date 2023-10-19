package account.businesslayer

import account.persistence.AppUserRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.stereotype.Component
import org.springframework.web.servlet.support.ServletUriComponentsBuilder
import java.util.*
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse


@Component
class RestAuthenticationEntryPoint : AuthenticationEntryPoint {

    @Autowired
    lateinit var auditService: AuditService

    @Autowired
    lateinit var userService: AppUserService

    @Autowired
    lateinit var userRepository: AppUserRepository

    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException
    ) {

        println("::::::::::RestAuthenticationEntryPoint:::::::::::::::::::")
        val authorization = request.getHeader("Authorization")
        println("authorization = $authorization")

        if (authorization != null) {
            println("in authorization != null")
            println(authorization.split(" "))
            println("Decoded = ${Base64.getDecoder().decode(authorization.split(" ")[1])}")

            // Remove "Basic " from the header
            val base64Credentials = authorization.substring("Basic ".length)
            val credentials = String(Base64.getDecoder().decode(base64Credentials))

            // credentials = username:password
            val values = credentials.split(":", limit = 2)
            println(values)

            val username = values[0]

            val path = ServletUriComponentsBuilder.fromCurrentRequest().build().path

            if (userRepository.findUserByEmailIgnoreCase(username) == null)
                auditService.logEvent(Action.LOGIN_FAILED, username, path, path)
            else {
                val user: AppUser? = userRepository.findUserByEmailIgnoreCase(username)

                if (user != null) {
                    if (user.isAccountNonLocked) {
                        auditService.logEvent(Action.LOGIN_FAILED, user.email, path, path)

                        if (!user.roles.contains(Role.ROLE_ADMINISTRATOR)) userService.increaseFailedAttempts(
                            user,
                            path!!
                        )

                    }
                }

            }
        }

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.message)
    }
}