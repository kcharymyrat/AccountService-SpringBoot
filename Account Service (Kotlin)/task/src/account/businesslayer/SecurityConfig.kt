package account.businesslayer

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.AccessDeniedHandler
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

@Configuration
open class SecurityConfig(private val restAuthenticationEntryPoint: RestAuthenticationEntryPoint) {

    @Autowired
    lateinit var accessDeniedHandler: AccessDeniedHandler

    @Bean
    @Throws(Exception::class)
    open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http
            .exceptionHandling().accessDeniedHandler(accessDeniedHandler)
            .and()
            .httpBasic(Customizer.withDefaults()) // Default Basic auth config
            .exceptionHandling { ex -> ex.authenticationEntryPoint(restAuthenticationEntryPoint) }
            .csrf { it.disable() }                // for POST requests via Postman
            .headers { headers -> headers.frameOptions().disable() } // for H2 console
            .authorizeHttpRequests { auth ->
                auth
                .antMatchers(HttpMethod.POST, "/api/auth/singup").permitAll()
                .antMatchers(HttpMethod.POST, "/api/auth/changepass").hasAnyAuthority(
                    Role.ROLE_USER.name,
                    Role.ROLE_ACCOUNTANT.name,
                    Role.ROLE_ADMINISTRATOR.name)
                .antMatchers(HttpMethod.GET, "/api/empl/payment").hasAnyAuthority(
                    Role.ROLE_USER.name,
                    Role.ROLE_ACCOUNTANT.name)
                .antMatchers(HttpMethod.POST, "/api/acct/payments").hasAuthority(Role.ROLE_ACCOUNTANT.name)
                .antMatchers(HttpMethod.PUT, "/api/acct/payments").hasAuthority(Role.ROLE_ACCOUNTANT.name)
                .antMatchers("/api/admin/**").hasAuthority(Role.ROLE_ADMINISTRATOR.name)
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



