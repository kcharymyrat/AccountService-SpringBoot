package account.businesslayer

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class AppUserAdapter(private val user: AppUser) : UserDetails {
    override fun getAuthorities(): Collection<GrantedAuthority> {
        val authorities: MutableList<GrantedAuthority> = ArrayList()

        user.roles.forEach { role: Role ->
            authorities.add(
                SimpleGrantedAuthority(role.toString())
            )
        }

        return authorities
    }

    override fun getPassword(): String = requireNotNull(user.password)

    override fun getUsername(): String = requireNotNull(user.email)

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true

    override fun isCredentialsNonExpired(): Boolean = true

    override fun isEnabled(): Boolean = true

    fun grantAuthority(authority: Role) {
        user.roles.add(authority)
    }

    fun removeAuthority(authority: Role) {
        user.roles.remove(authority)
    }
}