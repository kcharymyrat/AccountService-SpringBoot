package account.businesslayer

import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.Id


@Entity
class AppUser(
    @Id @GeneratedValue var id: Long? = null,
    var name: String? = null,
    var lastname: String? = null,
    var email: String? = null,
    var password: String? = null,
    var authority: String? = null
)