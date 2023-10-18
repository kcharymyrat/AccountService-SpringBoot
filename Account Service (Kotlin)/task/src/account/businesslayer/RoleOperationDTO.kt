package account.businesslayer

import com.fasterxml.jackson.annotation.JsonProperty

data class RoleOperationDTO (

    @JsonProperty("user")
    var email: String = "",

    var role: String = "",
    var operation: String = ""

) {
    constructor() : this("", "", "")
}