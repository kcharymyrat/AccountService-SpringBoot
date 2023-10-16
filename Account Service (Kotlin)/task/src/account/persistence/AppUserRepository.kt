package account.persistence

import account.businesslayer.AppUser
import org.springframework.data.repository.CrudRepository

interface AppUserRepository : CrudRepository<AppUser, Int> {
    fun findAppUserByEmail(email: String): AppUser?
}