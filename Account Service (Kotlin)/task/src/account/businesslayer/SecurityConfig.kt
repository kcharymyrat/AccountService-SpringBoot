package account.businesslayer

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

@Configuration
open class SecurityConfig(private val restAuthenticationEntryPoint: RestAuthenticationEntryPoint) {

    @Bean
    @Throws(Exception::class)
    open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .httpBasic(Customizer.withDefaults()) // Default Basic auth config
            .exceptionHandling { ex -> ex.authenticationEntryPoint(restAuthenticationEntryPoint) }
            .csrf { it.disable() }                // for POST requests via Postman
            .headers { headers -> headers.frameOptions().disable() } // for H2 console
            .authorizeHttpRequests { auth ->
                auth.mvcMatchers("/h2-console/**").permitAll()
                auth.mvcMatchers(HttpMethod.POST, "/api/auth/signup").permitAll()
//                auth.mvcMatchers(HttpMethod.GET, "/api/empl/payment").hasAnyRole(Role.ROLE_USER.toString(), Role.ROLE_ADMINISTRATOR.toString())
                auth.mvcMatchers(HttpMethod.GET, "/api/empl/payment").permitAll()
                auth.mvcMatchers(HttpMethod.POST, "/api/auth/changepass").authenticated()
                auth.mvcMatchers(HttpMethod.POST, "/api/acct/payments").permitAll()
                auth.mvcMatchers(HttpMethod.PUT, "/api/acct/payments").permitAll()
//                auth.mvcMatchers(HttpMethod.GET, "/api/admin/user").permitAll()
//                auth.mvcMatchers(HttpMethod.DELETE, "/api/admin/user").permitAll()
            }
            .sessionManagement { sessions ->
                sessions.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // no session
            }

        return http.build()
    }

    @Bean
    open fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder(13)
    }
}



