package account.persistence

import account.businesslayer.AppUser
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface AppUserRepository : CrudRepository<AppUser, Long> {
    @Query
    fun findUserByEmailIgnoreCase(email: String): AppUser?
}