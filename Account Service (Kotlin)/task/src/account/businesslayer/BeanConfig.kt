package account.businesslayer



import account.persistence.BreachedPasswordRepository
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.access.AccessDeniedHandler
import java.util.*
import java.util.function.Consumer
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import kotlin.collections.HashSet
import kotlin.collections.LinkedHashMap

@Configuration
open class BeanConfig {

    @Autowired
    lateinit var userService: AppUserService

    @Autowired
    lateinit var auditService: AuditService

    @Bean
    open fun authenticationProvider(): DaoAuthenticationProvider {
        println("authenticationProvider")
        val provider = DaoAuthenticationProvider()

        provider.setPasswordEncoder(getEncoder())
        provider.setUserDetailsService(userService)

        return provider
    }
    @Bean
    open fun getEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    open fun commandLineRunner(breachedPasswordRepository: BreachedPasswordRepository): CommandLineRunner {
        return CommandLineRunner {

            val breachedPasswords: Set<String> = HashSet(
                setOf(
                    "PasswordForJanuary", "PasswordForFebruary", "PasswordForMarch", "PasswordForApril",
                    "PasswordForMay", "PasswordForJune", "PasswordForJuly", "PasswordForAugust",
                    "PasswordForSeptember", "PasswordForOctober", "PasswordForNovember", "PasswordForDecember"
                )
            )

            breachedPasswords.forEach(Consumer { pass: String ->
                breachedPasswordRepository.save(
                    BreachedPassword(password = pass)
                )
            })

        }
    }

    @Bean
    open fun getAccessDeniedHandler(): AccessDeniedHandler {
        println("+++++++++++++++++++++++++++++getAccessDeniedHandler++++++++++++++++++++++")

        return AccessDeniedHandler { request: HttpServletRequest,
                                     response: HttpServletResponse,
                                     _: AccessDeniedException ->

            response.status = HttpStatus.FORBIDDEN.value()

            val data: MutableMap<String, Any> = LinkedHashMap()

            data["timestamp"] = Calendar.getInstance().time
            data["status"] = HttpStatus.FORBIDDEN.value()
            data["error"] = "Forbidden"
            data["message"] = "Access Denied!"
            data["path"] = request.requestURI

            auditService.logEvent(
                Action.ACCESS_DENIED,
                request.remoteUser,
                request.servletPath,
                request.servletPath
            )

            response.outputStream
                .println(ObjectMapper().writeValueAsString(data))
        }
    }

}