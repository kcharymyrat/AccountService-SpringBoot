package account.persistence

import account.businesslayer.AppUser
import org.springframework.data.repository.CrudRepository

interface AppUserRepository : CrudRepository<AppUser, Long> {
    fun findAppUserByEmail(email: String): AppUser?
    fun deleteByEmail(email: String): Int
}