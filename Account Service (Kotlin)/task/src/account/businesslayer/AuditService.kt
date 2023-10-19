package account.businesslayer

import account.persistence.EventRepository
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service


@Service
class AuditService {

    @Autowired
    lateinit var eventRepository: EventRepository

    fun getSecurityEvents(): MutableList<Event> {
        val evenList: MutableList<Event> = eventRepository.findAll() as MutableList<Event>

        evenList.sortedBy { it.id }

        return evenList
    }

    fun logEvent(
        action: Action,
        subject: String?,
        f_object: String?,
        path: String?
    ) {
        val event = Event()

        event.action = action
        event.subject = subject ?: "Anonymous"
        event.f_object = f_object
        event.path = path

        eventRepository.save(event)
    }
}