package account.businesslayer

import com.fasterxml.jackson.annotation.JsonProperty
import javax.validation.constraints.NotBlank

data class NewUserPasswordDTO(

    var email: String = "",

    @field:JsonProperty("new_password")
    @field:NotBlank
    var new_password: String = ""

) {
    constructor() : this("", "")
}