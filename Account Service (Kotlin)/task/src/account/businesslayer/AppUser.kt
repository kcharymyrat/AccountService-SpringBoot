package account.businesslayer

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.hibernate.annotations.SortNatural
import javax.persistence.*
import javax.validation.constraints.NotBlank


@Entity
class AppUser(
    @Id @GeneratedValue var id: Long? = null,
    var name: String? = null,
    var lastname: String? = null,
    var email: String? = null,

    @field:NotBlank
    @field:JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @field:Column
    var password: String = "",

    @field:Enumerated(EnumType.STRING)
    @field:ElementCollection(fetch = FetchType.EAGER)
    @field:SortNatural
    @field:Column
    var roles: MutableList<Role> = mutableListOf()
)