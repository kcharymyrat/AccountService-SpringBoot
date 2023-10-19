package account.businesslayer

enum class Message(val message: String) {
    SIGNUP("The password length must be at least 12 chars!"),
    CHECK_PASSWORD("Password length must be 12 chars minimum!")
}