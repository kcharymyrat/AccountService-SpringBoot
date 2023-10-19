package account.businesslayer

import account.persistence.AppUserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class AppUserDetailsImpl(private val repository: AppUserRepository) : UserDetailsService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(email: String): UserDetails {
        val user = repository.findUserByEmailIgnoreCase(email.lowercase())
            ?: throw UsernameNotFoundException("User not found: $email")

        return AppUserAdapter(user)
    }

}