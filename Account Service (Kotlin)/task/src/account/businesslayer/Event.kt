package account.businesslayer

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import org.hibernate.annotations.CreationTimestamp
import java.time.LocalDateTime
import javax.persistence.Column
import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
data class Event(

    @field:Id
    @field:GeneratedValue(strategy = GenerationType.TABLE)
    @field:JsonIgnore
    var id: Long = 0,

    @field:Column
    @field:CreationTimestamp
    var date: LocalDateTime = LocalDateTime.now(),

    @field:Column
    var action: Action = Action.CREATE_USER,

    @field:Column
    var subject: String = "",

    @field:Column
    @JsonProperty("object")
    var f_object: String? = "",

    @field:Column
    var path: String? = ""

) {
    constructor() : this(0L, LocalDateTime.now(), Action.CREATE_USER, "", "", "")
}