package account.businesslayer

import com.fasterxml.jackson.annotation.JsonProperty
import org.springframework.data.annotation.ReadOnlyProperty

data class UserAccessDTO(

    @field:JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    var user: String = "",

    @field:JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    var operation: Operation = Operation.UNLOCK,

    @field:ReadOnlyProperty
    var status: String = ""

) {
    constructor() : this("", Operation.UNLOCK, "")
}