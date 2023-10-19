package account.businesslayer

import account.persistence.AppUserRepository
import account.persistence.PaymentRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import java.time.DateTimeException
import java.time.YearMonth
import java.time.format.DateTimeFormatter
import java.util.*

@Service
class PaymentService {

    @Autowired
    lateinit var paymentRepository: PaymentRepository

    @Autowired
    lateinit var userRepository: AppUserRepository

    fun uploadPayrolls(payments: List<Payment>): ResponseEntity<Map<String, String>> {
        validatePayment(payments)
        paymentRepository.saveAll(payments)

        return ResponseEntity(mapOf("status" to "Added successfully!"), HttpStatus.OK)
    }

    fun updatePayment(payment: Payment): ResponseEntity<Map<String, String>> {
        checkEmployeeExistence(payment.employee)
        validateSalary(payment)

        val p: Payment =
            paymentRepository
                .findPaymentByEmployeeIgnoreCaseAndPeriod(
                    payment.employee, payment.period) ?: throw EmployeeNotFoundException()

        p.salary = payment.salary
        paymentRepository.save(p)

        return ResponseEntity(mapOf("status" to "Updated successfully!"), HttpStatus.OK)
    }

    fun getPaymentForPeriod(period: String?, user: AppUser): ResponseEntity<*> {
        return if (period == null) {

            val payments: List<Payment> = paymentRepository.findPaymentByEmployeeIgnoreCase(user.email)

            payments.sortedBy { it.period }.reversed()

            val responses: MutableList<EmployeePaymentResponseDTO> = ArrayList()

            for (payment in payments) {
                responses.add(createResponse(payment, user))
            }

            ResponseEntity(responses, HttpStatus.OK)

        } else {

            val payment: Payment = paymentRepository.findPaymentByEmployeeIgnoreCaseAndPeriod(
                user.email,
                getYearMonthFromString(period)
            ) ?: throw PaymentNotFoundException()

            val response: EmployeePaymentResponseDTO = createResponse(payment, user)

            ResponseEntity(response, HttpStatus.OK)

        }
    }

    private fun createResponse(payment: Payment, user: AppUser): EmployeePaymentResponseDTO {
        val formatter = DateTimeFormatter.ofPattern("MMMM-yyyy", Locale.ENGLISH)
        val response = EmployeePaymentResponseDTO()

        response.name = user.name
        response.lastname = user.lastname
        response.period = payment.period.format(formatter)
        response.salary = "${payment.salary / 100} dollar(s) ${payment.salary % 100} cent(s)"

        return response
    }

    private fun validatePayment(payments: List<Payment>) {
        for (payment in payments) {
            validateSalary(payment)
            checkEmployeeExistence(payment.employee)
            checkDuplicatePayment(payment)
        }
    }

    private fun validateSalary(payment: Payment) {
        if (payment.salary < 0) throw SalaryException()
    }

    private fun checkEmployeeExistence(employee: String) {
        if (userRepository.findUserByEmailIgnoreCase(employee) == null) throw EmployeeNotFoundException()
    }

    private fun checkDuplicatePayment(payment: Payment) {
        val payments: List<Payment> = paymentRepository.findPaymentByEmployeeIgnoreCase(payment.employee)

        if (payments.stream().anyMatch(payment::equals)) throw DuplicatePaymentException()
    }

    private fun getYearMonthFromString(period: String): YearMonth {

        val yearMonth = try {
            YearMonth.parse(period, DateTimeFormatter.ofPattern("MM-yyyy"))
        } catch (e: DateTimeException) {
            throw WrongPeriodException()
        }

        return yearMonth
    }
}