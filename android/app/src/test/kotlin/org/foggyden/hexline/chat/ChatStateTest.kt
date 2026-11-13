package org.foggyden.hexline.chat

import org.foggyden.hexline.core.ChatLine
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.Status
import org.foggyden.hexline.core.User
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    private fun shown(s: ChatState) =
        s.entries.map {
            when (it) {
                is Entry.Line -> it.line.text
                is Entry.Notice -> "notice: ${it.text}"
                is Entry.Broadcast -> "broadcast: ${it.nick}: ${it.text}"
                is Entry.NotSent -> "not sent: ${it.why}"
            }
        }

    private fun ChatState.after(vararg updates: CoreUpdate) = updates.fold(this) { acc, u -> acc.apply(u) }

    private val live = ChatState().apply(CoreUpdate.Roster(1u, listOf(user(1, "alice"), user(2, "bob")), "welcome"))

    @Test
    fun theRosterMakesTheLinkLiveAndUsersComeChangeAndGo() {
        assertEquals(Link.Live, live.link)
        assertEquals("welcome", live.subject)
        val s =
            live.after(
                CoreUpdate.UserJoined(user(3, "cy")),
                CoreUpdate.UserJoined(user(3, "cy")),
                CoreUpdate.UserChanged(user(2, "bob", Status.DETACHED)),
                CoreUpdate.UserParted(1u),
            )
        assertEquals(listOf("cy" to Status.ACTIVE, "bob" to Status.DETACHED), s.users.map { it.nick to it.status })
    }

    @Test
    fun theLobbysLinesAndNoticesAreShownAndARoomsAreNot() {
        val s =
            live.after(
                CoreUpdate.Chat(line(10, "hi")),
                CoreUpdate.Chat(line(11, "in a room", room = 4)),
                CoreUpdate.Notice("bob was kicked", null),
                CoreUpdate.Notice("room notice", 4uL),
                CoreUpdate.Subject("room topic", 4uL),
                CoreUpdate.Broadcast("admin", "restart soon"),
                CoreUpdate.Other("msg", "{}"),
            )
        assertEquals(listOf("hi", "notice: bob was kicked", "broadcast: admin: restart soon"), shown(s))
        assertEquals("welcome", s.subject)
        assertEquals(
            s.entries
                .map { it.key }
                .toSet()
                .size,
            s.entries.size,
        )
    }

    @Test
    fun anEndIsToldByWhatCameBeforeIt() {
        val cases =
            listOf(
                live.after(CoreUpdate.Kicked, CoreUpdate.Closed(false, false)) to Why.Kicked,
                live.after(CoreUpdate.Closed(false, true)) to Why.Replaced,
                live.after(CoreUpdate.Closed(true, false)) to Why.Lost,
                live.copy(leaving = true).after(CoreUpdate.Closed(true, false)) to null,
            )
        for ((s, why) in cases) assertEquals(Link.Ended(why), s.link)
    }

    @Test
    fun aLineIsShownOnceWhicheverWayItArrivesFirst() {
        val liveFirst = live.after(CoreUpdate.Chat(line(12, "live"))).withEarlier(listOf(line(11, "old"), line(12, "live")), true)
        assertEquals(listOf("old", "live"), shown(liveFirst))
        val historyFirst = live.withEarlier(listOf(line(11, "old"), line(12, "live")), true).after(CoreUpdate.Chat(line(12, "live")))
        assertEquals(listOf("old", "live"), shown(historyFirst))
    }

    @Test
    fun pagingGoesBackFromTheOldestLineWithAnIdAndStopsWhereThereIsNone() {
        val s = live.after(CoreUpdate.Notice("hello", null), CoreUpdate.Chat(line(12, "live")))
        assertEquals(12uL, s.oldestId)
        val paged = s.withEarlier(listOf(line(10, "older"), line(11, "old")), hasMore = true)
        assertEquals(listOf("older", "old", "notice: hello", "live"), shown(paged))
        assertEquals(10uL, paged.oldestId)
        assertTrue(paged.earlierToLoad)
        assertFalse(paged.withEarlier(emptyList(), hasMore = false).earlierToLoad)
        // A page that leaves no older id to page from ends it, whatever it says.
        val idless = live.withEarlier(listOf(line(null, "from a server keeping no ids")), hasMore = true)
        assertNull(idless.oldestId)
        assertFalse(idless.earlierToLoad)
        assertFalse(paged.withEarlier(listOf(line(10, "older")), hasMore = true).earlierToLoad)
    }

    @Test
    fun aMessageNotSentIsShownInItsPlace() {
        assertEquals(listOf("not sent: ${Why.Lost}"), shown(live.notSent(Why.Lost)))
    }
}
