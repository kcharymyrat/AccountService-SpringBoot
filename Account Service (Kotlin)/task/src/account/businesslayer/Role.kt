package account.businesslayer

enum class Role(private val role: String) {

    ROLE_USER("ROLE_USER"),
    ROLE_ADMINISTRATOR("ROLE_ADMINISTRATOR"),
    ROLE_ACCOUNTANT("ROLE_ACCOUNTANT");

    override fun toString(): String {
        return role
    }

}