package account.businesslayer

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.hibernate.annotations.SortNatural
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import javax.persistence.*
import javax.validation.constraints.Email
import javax.validation.constraints.NotBlank
import javax.validation.constraints.Pattern


@Entity
class AppUser(
    @field:Id
    @field:GeneratedValue(strategy = GenerationType.AUTO)
    @field:JsonProperty(access = JsonProperty.Access.READ_ONLY)
    private var id: Long = 0,

    @field:NotBlank
    @field:Column
    var name: String = "",

    @field:NotBlank
    @field:Column
    var lastname: String = "",

    @field:Email
    @field:Pattern(regexp = ".+(@acme.com)$")
    @field:Column
    var email: String = "",

    @field:NotBlank
    @field:JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @field:Column
    private var password: String = "",

    @field:Enumerated(EnumType.STRING)
    @field:ElementCollection(fetch = FetchType.EAGER)
    @field:SortNatural
    @field:Column
    var roles: MutableList<Role> = mutableListOf(),

    @field:JsonIgnore
    @field:Column
    private var isNonLocked: Boolean = false,

    @field:JsonIgnore
    @field:Column
    var failedAttempts: Int = 0

) : UserDetails {

    @JsonIgnore
    override fun getAuthorities(): Collection<GrantedAuthority> {
        val authorities: MutableList<GrantedAuthority> = ArrayList()

        roles.forEach { role: Role ->
            authorities.add(
                SimpleGrantedAuthority(role.toString())
            )
        }

        return authorities
    }

    @JsonIgnore
    override fun getPassword(): String {
        return password
    }

    @JsonIgnore
    fun setPassword(password: String) {
        this.password = password
    }

    @JsonIgnore
    override fun getUsername(): String {
        return email
    }

    @JsonIgnore
    override fun isAccountNonExpired(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isAccountNonLocked(): Boolean {
        return isNonLocked
    }

    @JsonIgnore
    fun setIsAccountNonLocked(isNonLocked: Boolean) {
        this.isNonLocked = isNonLocked
    }

    @JsonIgnore
    override fun isCredentialsNonExpired(): Boolean {
        return true
    }

    @JsonIgnore
    override fun isEnabled(): Boolean {
        return true
    }

    @JsonIgnore
    fun grantAuthority(authority: Role) {
        roles.add(0, authority)
    }

    @JsonIgnore
    fun removeAuthority(authority: Role) {
        roles.remove(authority)
    }

    @JsonIgnore
    fun isNonLocked(): Boolean {
        return isNonLocked
    }

}