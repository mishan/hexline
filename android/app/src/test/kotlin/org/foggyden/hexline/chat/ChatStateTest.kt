package org.foggyden.hexline.chat

import org.foggyden.hexline.core.ChatLine
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.Status
import org.foggyden.hexline.core.User
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ChatStateTest {
    private fun user(
        uid: Int,
        nick: String,
        status: Status = Status.ACTIVE,
    ) = User(uid.toUShort(), nick, 128u, false, status, false)

    private fun line(
        id: Long?,
        text: String,
        room: Long? = null,
    ) = ChatLine(id?.toULong(), null, "alice", text, 0u, false, room?.toULong(), false)

    private fun texts(s: ChatState) =
        s.entries.map {
            when (it) {
                is Entry.Line -> it.line.text
                is Entry.Notice -> "notice: ${it.text}"
            }
        }

    private val live =
        ChatState().apply(CoreUpdate.Roster(1u, listOf(user(1, "alice"), user(2, "bob")), "welcome"))

    @Test
    fun theRosterMakesTheLinkLiveAndUsersComeChangeAndGo() {
        assertEquals(Link.Live, live.link)
        assertEquals("welcome", live.subject)
        val s =
            listOf(
                CoreUpdate.UserJoined(user(3, "cy")),
                CoreUpdate.UserChanged(user(2, "bob", Status.DETACHED)),
                CoreUpdate.UserParted(1u),
            ).fold(live) { acc, u -> acc.apply(u) }
        assertEquals(listOf("bob" to Status.DETACHED, "cy" to Status.ACTIVE), s.users.map { it.nick to it.status })
    }

    @Test
    fun theLobbysLinesAndNoticesAreShownAndARoomsAreNot() {
        val s =
            listOf(
                CoreUpdate.Chat(line(10, "hi")),
                CoreUpdate.Chat(line(11, "in a room", room = 4)),
                CoreUpdate.Notice("bob was kicked", null),
                CoreUpdate.Notice("room notice", 4uL),
                CoreUpdate.Subject("room topic", 4uL),
                CoreUpdate.Broadcast("admin", "restart soon"),
                CoreUpdate.Other("msg", "{}"),
            ).fold(live) { acc, u -> acc.apply(u) }
        assertEquals(listOf("hi", "notice: bob was kicked", "notice: admin: restart soon"), texts(s))
        assertEquals("welcome", s.subject)
    }

    @Test
    fun anEndIsToldByWhatCameBeforeIt() {
        val cases =
            listOf(
                listOf(CoreUpdate.Kicked, CoreUpdate.Closed(false, false)) to "You were disconnected by the server.",
                listOf(CoreUpdate.Closed(false, true)) to "This session was opened somewhere else.",
                listOf(CoreUpdate.Closed(true, false)) to "The connection was lost.",
            )
        for ((updates, why) in cases) {
            assertEquals(Link.Ended(why), updates.fold(live) { acc, u -> acc.apply(u) }.link)
        }
    }

    @Test
    fun earlierHistoryGoesFirstAndALineAlreadyShownIsNotShownTwice() {
        val s = live.apply(CoreUpdate.Chat(line(12, "live")))
        val joined = s.withEarlier(listOf(line(10, "older"), line(11, "old"), line(12, "live")), hasMore = true)
        assertEquals(listOf("older", "old", "live"), texts(joined))
        assertEquals(10uL, joined.oldestId)
        assertTrue(joined.earlierToLoad)
        assertFalse(joined.withEarlier(emptyList(), hasMore = false).earlierToLoad)
    }
}
