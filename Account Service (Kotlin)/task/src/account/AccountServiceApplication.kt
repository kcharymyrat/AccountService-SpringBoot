package account

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication


@SpringBootApplication
open class AccountServiceApplication

fun main(args: Array<String>) {
    println("Hmm")
    runApplication<AccountServiceApplication>(*args)
}