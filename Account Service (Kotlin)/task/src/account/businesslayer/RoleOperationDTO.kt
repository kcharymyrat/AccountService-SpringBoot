package account.businesslayer

import com.fasterxml.jackson.annotation.JsonProperty

data class RoleOperationDTO (

    @field:JsonProperty("user")
    var email: String = "",

    var role: String = "",
    var operation: String = ""

) {
    constructor() : this("", "", "")
}