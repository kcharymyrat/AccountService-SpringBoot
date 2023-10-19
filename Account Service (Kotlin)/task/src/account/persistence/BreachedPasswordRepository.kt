package account.persistence

import account.businesslayer.BreachedPassword
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository

@Repository
interface BreachedPasswordRepository : CrudRepository<BreachedPassword, Long> {
    @Query
    fun existsBreachedPasswordsByPassword(password: String): Boolean
}