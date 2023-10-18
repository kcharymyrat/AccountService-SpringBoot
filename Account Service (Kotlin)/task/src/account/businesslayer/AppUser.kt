package account.businesslayer

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.hibernate.annotations.SortNatural
import javax.persistence.*


@Entity
class AppUser(
    @Id @GeneratedValue var id: Long? = null,
    var name: String? = null,
    var lastname: String? = null,
    var email: String? = null,
    var password: String? = null,

    @field:JsonIgnore
    @field:Enumerated(EnumType.STRING)
    @field:ElementCollection(fetch = FetchType.EAGER)
    @field:SortNatural
    @field:Column
    val roles: MutableList<Role> = mutableListOf()
)