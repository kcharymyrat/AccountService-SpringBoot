package account.businesslayer

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.web.access.AccessDeniedHandler


@Configuration
@EnableWebSecurity
open class WebSecurityConfig : WebSecurityConfigurerAdapter() {

    @Autowired
    lateinit var authenticationEntryPoint: RestAuthenticationEntryPoint

    @Autowired
    lateinit var authenticationProvider: DaoAuthenticationProvider

    @Autowired
    lateinit var accessDeniedHandler: AccessDeniedHandler

    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.authenticationProvider(authenticationProvider)
    }

    override fun configure(http: HttpSecurity) {
        http.httpBasic()
            .authenticationEntryPoint(authenticationEntryPoint) // Handle auth error
            .and()
            .csrf().disable().headers().frameOptions().disable() // for Postman, the H2 console
            .and()
            .exceptionHandling().accessDeniedHandler(accessDeniedHandler)
            .and()
            .authorizeRequests()
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
            .antMatchers(HttpMethod.GET, "/api/security/**").hasAuthority(Role.ROLE_AUDITOR.name)
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS); // no session
    }

}


