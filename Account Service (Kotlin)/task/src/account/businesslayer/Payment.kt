package account.businesslayer

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonIgnore
import java.time.YearMonth
import java.time.YearMonth.now
import java.util.Objects
import javax.persistence.*



@Entity
@Table(uniqueConstraints = [UniqueConstraint(columnNames = ["employee", "period"])])
data class Payment(

    @Id @GeneratedValue var id: Long? = null,

    @field:Column
    var employee: String = "",

    @field:Column
    var period: YearMonth = YearMonth.now(),

    @field:Column
    var salary: Long = 0

) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || javaClass != other.javaClass) return false

        val payment: Payment = other as Payment

        return Objects.equals(employee, payment.employee) && Objects.equals(period, payment.period)
    }

    override fun hashCode(): Int {
        return Objects.hash(employee, period)
    }
}

