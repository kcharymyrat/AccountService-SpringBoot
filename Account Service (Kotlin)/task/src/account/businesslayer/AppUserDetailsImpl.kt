package account.businesslayer

import account.persistence.AppUserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
class AppUserDetailsImpl(private val repository: AppUserRepository) : UserDetailsService {

    @Throws(UsernameNotFoundException::class)
    override fun loadUserByUsername(email: String): UserDetails {
        val user = repository.findAppUserByEmail(email.lowercase())
            ?: throw UsernameNotFoundException("User not found: $email")

        return AppUserAdapter(user)
    }

//    fun addNewUser(user: AppUser): AppUser {
//        if (repository.findAll().any { user.email.equals(it.email, true) }) {
//            throw UserExistsException()
//        }
//        user.authority = Role.USER.toString()
//        return repository.save(user)
//    }
}