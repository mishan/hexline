package org.foggyden.hexline.chat

import org.foggyden.hexline.core.ChatLine
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.User

/** Why a connection ended or never began; the screen says it in words. */
sealed interface Why {
    data object Kicked : Why

    /** Another device resumed the session. */
    data object Replaced : Why

    data object Lost : Why

    /** A saved session the server no longer has, with no password to log in again. */
    data object Expired : Why

    data object Unreachable : Why

    data object WrongPassword : Why

    data object Banned : Why

    data object Full : Why

    data object NotUnderstood : Why

    data class Refused(
        val code: String,
    ) : Why
}

/** A server's refusal, as the person is told it. */
fun refusal(code: String): Why =
    when (code) {
        "login_failed" -> Why.WrongPassword
        "kicked" -> Why.Kicked
        "session_expired" -> Why.Expired
        "replaced" -> Why.Replaced
        "banned" -> Why.Banned
        "server_full" -> Why.Full
        else -> Why.Refused(code)
    }

/** Where the connection stands, as the screen shows it. */
sealed interface Link {
    data object Idle : Link

    data object Connecting : Link

    data object Live : Link

    /** The link went and the core is getting it back: still the chat. */
    data class Reconnecting(
        val attempt: UInt,
    ) : Link

    /** Ended: `why` for the person, null when they ended it themselves. */
    data class Ended(
        val why: Why?,
    ) : Link
}

/** One row of the transcript. `key` is its own for the life of the screen. */
sealed interface Entry {
    val key: Long

    data class Line(
        override val key: Long,
        val line: ChatLine,
    ) : Entry

    data class Notice(
        override val key: Long,
        val text: String,
    ) : Entry

    data class Broadcast(
        override val key: Long,
        val nick: String,
        val text: String,
    ) : Entry

    /** Lines said while the link was down, more than were filled in. */
    data class Missed(
        override val key: Long,
    ) : Entry

    data class NotSent(
        override val key: Long,
        val why: Why,
    ) : Entry
}

/**
 * Everything one server's screen shows. Changed only by its functions, so
 * what the screen shows follows from the updates in the order the core
 * gave them, and is tested without a screen.
 */
data class ChatState(
    val link: Link = Link.Idle,
    val selfUid: UShort? = null,
    val users: List<User> = emptyList(),
    val subject: String = "",
    /** Oldest first. */
    val entries: List<Entry> = emptyList(),
    /** History older than the first line remains to be loaded. */
    val earlierToLoad: Boolean = true,
    val kicked: Boolean = false,
    /** The person chose to leave: the close that follows is no failure. */
    val leaving: Boolean = false,
    /** What the server said when it would not take the session back. */
    val refused: String? = null,
    /** Lines were missed after this one: history is to fill them in. */
    val fillAfter: ULong? = null,
    private val nextKey: Long = 0,
) {
    private val shownIds: Set<ULong> by lazy { entries.mapNotNullTo(HashSet()) { (it as? Entry.Line)?.line?.id } }

    private fun appended(entry: (Long) -> Entry) = copy(entries = entries + entry(nextKey), nextKey = nextKey + 1)

    fun apply(update: CoreUpdate): ChatState =
        when (update) {
            is CoreUpdate.Roster ->
                copy(link = Link.Live, selfUid = update.selfUid, users = update.users, subject = update.subject)
            is CoreUpdate.UserJoined -> copy(users = users.filter { it.uid != update.user.uid } + update.user)
            is CoreUpdate.UserChanged -> copy(users = users.filter { it.uid != update.user.uid } + update.user)
            is CoreUpdate.UserParted -> copy(users = users.filter { it.uid != update.uid })
            // Rooms come with a later slice; their lines are not the lobby's.
            // A line history already brought is not shown twice.
            is CoreUpdate.Chat ->
                when {
                    update.line.room != null -> this
                    update.line.id != null && update.line.id in shownIds -> this
                    else -> appended { Entry.Line(it, update.line) }
                }
            is CoreUpdate.Subject -> if (update.room == null) copy(subject = update.subject) else this
            is CoreUpdate.Notice -> if (update.room == null) appended { Entry.Notice(it, update.text) } else this
            is CoreUpdate.Broadcast -> appended { Entry.Broadcast(it, update.nick, update.text) }
            is CoreUpdate.Kicked -> copy(kicked = true)
            is CoreUpdate.Reconnecting -> copy(link = Link.Reconnecting(update.attempt))
            is CoreUpdate.Reconnected ->
                // From the earliest gap still open, so a second does not cut short the first.
                copy(link = Link.Live, fillAfter = if (update.gap) listOfNotNull(fillAfter, newestId).minOrNull() else fillAfter)
            is CoreUpdate.Refused -> copy(refused = update.code)
            is CoreUpdate.Closed ->
                copy(
                    link =
                        Link.Ended(
                            when {
                                kicked -> Why.Kicked
                                update.replaced -> Why.Replaced
                                leaving -> null
                                refused != null -> refusal(refused)
                                else -> Why.Lost
                            },
                        ),
                )
            is CoreUpdate.Other -> this
        }

    fun notSent(why: Why) = appended { Entry.NotSent(it, why) }

    /**
     * A page of history from before the first line shown, joined on: a line
     * already shown is not shown twice. A page that gives no older line to
     * page on from ends the paging, whatever it says of more.
     */
    fun withEarlier(
        page: List<ChatLine>,
        hasMore: Boolean,
    ): ChatState {
        val before = oldestId
        val earlier = page.filter { it.id == null || it.id !in shownIds }
        val keys = (nextKey until nextKey + earlier.size).iterator()
        val joined = copy(entries = earlier.map { Entry.Line(keys.next(), it) } + entries, nextKey = nextKey + earlier.size)
        return joined.copy(earlierToLoad = hasMore && joined.oldestId != null && joined.oldestId != before)
    }

    /**
     * A page of history from after [fillAfter], each line put among those
     * shown by its id, so lines said while the link was down fall before the
     * ones heard since. A page that adds nothing ends the filling.
     */
    fun withLater(
        page: List<ChatLine>,
        hasMore: Boolean,
    ): ChatState {
        val missed = page.filter { it.id != null && it.id !in shownIds }
        var next = nextKey
        val merged = entries.toMutableList()
        for (line in missed) {
            val at = merged.indexOfFirst { e -> (e as? Entry.Line)?.line?.id?.let { it > line.id!! } == true }
            merged.add(if (at < 0) merged.size else at, Entry.Line(next++, line))
        }
        val newest = missed.lastOrNull()?.id
        return copy(entries = merged, nextKey = next, fillAfter = if (hasMore && newest != null) newest else null)
    }

    /** Gives up filling, marking where the lines that were not filled belong. */
    fun withMissed(): ChatState {
        val after = fillAfter ?: return this
        val at = entries.indexOfFirst { e -> (e as? Entry.Line)?.line?.id?.let { it > after } == true }
        val marked = entries.toMutableList().apply { add(if (at < 0) size else at, Entry.Missed(nextKey)) }
        return copy(entries = marked, nextKey = nextKey + 1, fillAfter = null)
    }

    /** The newest line shown that has an id. */
    val newestId: ULong?
        get() = entries.mapNotNull { (it as? Entry.Line)?.line?.id }.maxOrNull()

    /** The id to page back from: the oldest line shown that has one. */
    val oldestId: ULong?
        get() = entries.firstNotNullOfOrNull { (it as? Entry.Line)?.line?.id }
}
