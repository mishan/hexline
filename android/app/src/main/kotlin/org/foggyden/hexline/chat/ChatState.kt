package org.foggyden.hexline.chat

import org.foggyden.hexline.core.ChatLine
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.User

/** Where the connection stands, as the screen shows it. */
sealed interface Link {
    data object Idle : Link

    data object Connecting : Link

    data object Live : Link

    /** Ended: `why` for the person, null when they ended it themselves. */
    data class Ended(
        val why: String?,
    ) : Link
}

/** One line of the transcript: someone's chat, or something the server said. */
sealed interface Entry {
    data class Line(
        val line: ChatLine,
    ) : Entry

    data class Notice(
        val text: String,
    ) : Entry
}

/**
 * Everything one server's screen shows. Changed only by [apply] and
 * [withEarlier], so what the screen shows follows from the updates in the
 * order the core gave them, and is tested without a screen.
 */
data class ChatState(
    val link: Link = Link.Idle,
    val selfUid: UShort? = null,
    val users: List<User> = emptyList(),
    val subject: String = "",
    val entries: List<Entry> = emptyList(),
    /** History older than the first line remains to be loaded. */
    val earlierToLoad: Boolean = true,
    val kicked: Boolean = false,
) {
    fun apply(update: CoreUpdate): ChatState =
        when (update) {
            is CoreUpdate.Roster ->
                copy(link = Link.Live, selfUid = update.selfUid, users = update.users, subject = update.subject)
            is CoreUpdate.UserJoined -> copy(users = users.filter { it.uid != update.user.uid } + update.user)
            is CoreUpdate.UserChanged -> copy(users = users.map { if (it.uid == update.user.uid) update.user else it })
            is CoreUpdate.UserParted -> copy(users = users.filter { it.uid != update.uid })
            // Rooms come with a later slice; their lines are not the lobby's.
            is CoreUpdate.Chat -> if (update.line.room == null) copy(entries = entries + Entry.Line(update.line)) else this
            is CoreUpdate.Subject -> if (update.room == null) copy(subject = update.subject) else this
            is CoreUpdate.Notice -> if (update.room == null) copy(entries = entries + Entry.Notice(update.text)) else this
            is CoreUpdate.Broadcast -> copy(entries = entries + Entry.Notice("${update.nick}: ${update.text}"))
            is CoreUpdate.Kicked -> copy(kicked = true)
            is CoreUpdate.Closed ->
                copy(
                    link =
                        Link.Ended(
                            when {
                                kicked -> "You were disconnected by the server."
                                update.replaced -> "This session was opened somewhere else."
                                else -> "The connection was lost."
                            },
                        ),
                )
            is CoreUpdate.Other -> this
        }

    /**
     * A page of history from before the first line shown, joined on: a line
     * already shown (live, and in the page too) is not shown twice.
     */
    fun withEarlier(
        page: List<ChatLine>,
        hasMore: Boolean,
    ): ChatState {
        val shown = entries.mapNotNullTo(HashSet()) { (it as? Entry.Line)?.line?.id }
        val earlier = page.filter { it.id == null || it.id !in shown }.map(Entry::Line)
        return copy(entries = earlier + entries, earlierToLoad = hasMore)
    }

    /** The id to page back from: the oldest line shown that has one. */
    val oldestId: ULong?
        get() = entries.firstNotNullOfOrNull { (it as? Entry.Line)?.line?.id }
}
