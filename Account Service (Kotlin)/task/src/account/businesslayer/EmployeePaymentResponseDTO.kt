package account.businesslayer

data class EmployeePaymentResponseDTO(
    var name: String = "",
    var lastname: String = "",
    var period: String = "",
    var salary: String = ""
) {
    constructor(): this("", "", "", "")
}