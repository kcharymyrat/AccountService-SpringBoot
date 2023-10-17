package account.persistence

import account.businesslayer.Payment
import org.springframework.data.repository.CrudRepository
import org.springframework.stereotype.Repository
import java.time.YearMonth

@Repository
interface PaymentRepository : CrudRepository<Payment, Long> {
    fun findPaymentByEmployeeIgnoreCase(email: String): List<Payment>
    fun findPaymentByEmployeeIgnoreCaseAndPeriod(email: String, period: YearMonth): Payment?
}