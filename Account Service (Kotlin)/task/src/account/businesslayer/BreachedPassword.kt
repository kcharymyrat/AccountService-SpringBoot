package account.businesslayer

import javax.persistence.*


@Entity(name = "breached_passwords")
data class BreachedPassword(

    @field:Id
    @field:GeneratedValue(strategy = GenerationType.SEQUENCE)
    var id: Long = 0,

    @field:Column
    var password: String = ""

) {
    constructor() : this(0, "")
}