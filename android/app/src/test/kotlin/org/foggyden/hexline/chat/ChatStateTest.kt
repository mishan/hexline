package org.foggyden.hexline.chat

import org.foggyden.hexline.core.ChatLine
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.LoginInfo
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
                is Entry.Missed -> "missed more"
                is Entry.SignedIn -> "signed in: ${it.outcome}"
            }
        }

    private fun ChatState.after(vararg updates: CoreUpdate) = updates.fold(this) { acc, u -> acc.apply(u) }

    private val live = ChatState().apply(CoreUpdate.Roster(1u, listOf(user(1, "alice"), user(2, "bob")), "welcome"))

    @Test
    fun aLoginAfterALapseThatLandsOtherwiseIsTold() {
        val linked = live.signedIn("linked")
        val back = { outcome: String -> CoreUpdate.Reconnected(true, LoginInfo("s", emptyList(), true, "fp", outcome, false)) }
        assertEquals(listOf("signed in: Account"), shown(linked))
        assertEquals(shown(linked), shown(linked.apply(back("linked"))))
        assertEquals(shown(linked) + "signed in: Guest", shown(linked.apply(back("guest"))))
    }

    @Test
    fun aPasswordLoginOrAnOutcomeThisAppDoesNotKnowAddsNoAside() {
        assertEquals(shown(live), shown(live.signedIn(null)))
        assertEquals(shown(live), shown(live.signedIn("someday")))
    }

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
                live.after(CoreUpdate.Refused("login_failed"), CoreUpdate.Closed(false, false)) to Why.WrongPassword,
            )
        for ((s, why) in cases) assertEquals(Link.Ended(why), s.link)
    }

    @Test
    fun aGapIsFilledFromTheNewestLineBeforeItInOrderAndOnce() {
        val before = live.after(CoreUpdate.Chat(line(10, "before")))
        assertNull(before.after(CoreUpdate.Reconnected(false, null)).fillAfter)
        // Line 13 arrives live once the link is back; 11 to 13 were said meanwhile.
        val back = before.after(CoreUpdate.Reconnected(true, null), CoreUpdate.Chat(line(13, "live")))
        assertEquals(10uL, back.fillAfter)
        val page = back.withLater(listOf(line(11, "missed"), line(12, "missed too")), hasMore = true)
        assertEquals(listOf("before", "missed", "missed too", "live"), shown(page))
        assertEquals("the next page goes on from the newest filled", 12uL, page.fillAfter)
        val done = page.withLater(listOf(line(13, "live")), hasMore = false)
        assertEquals(listOf("before", "missed", "missed too", "live"), shown(done))
        assertNull(done.fillAfter)
        assertNull("a page with nothing new ends it", page.withLater(emptyList(), hasMore = true).fillAfter)
        assertEquals(
            done.entries.size,
            done.entries
                .map { it.key }
                .toSet()
                .size,
        )
    }

    @Test
    fun aSecondGapWhileTheFirstIsFillingFillsFromTheEarlier() {
        val first = live.after(CoreUpdate.Chat(line(10, "before")), CoreUpdate.Reconnected(true, null))
        val second = first.after(CoreUpdate.Chat(line(20, "live")), CoreUpdate.Reconnected(true, null))
        assertEquals(10uL, second.fillAfter)
        assertNull("no line, no gap to fill", live.after(CoreUpdate.Reconnected(true, null)).fillAfter)
    }

    @Test
    fun aGapTooLongToFillIsMarkedWhereItIs() {
        val back =
            live.after(CoreUpdate.Chat(line(10, "before")), CoreUpdate.Reconnected(true, null), CoreUpdate.Chat(line(900, "live")))
        val page = back.withLater(listOf(line(11, "missed")), hasMore = true)
        val marked = page.withMissed()
        assertEquals(listOf("before", "missed", "missed more", "live"), shown(marked))
        assertNull(marked.fillAfter)
    }

    @Test
    fun aLapsedSessionIsToldAsOneToSignInToAgain() {
        assertEquals(Why.Expired, refusal("session_expired"))
    }

    @Test
    fun aLinkBeingGotBackIsStillTheChatUntilItIsBack() {
        val s = live.after(CoreUpdate.Reconnecting(2u))
        assertEquals(Link.Reconnecting(2u), s.link)
        assertEquals(live.users, s.users)
        assertEquals(Link.Live, s.after(CoreUpdate.Reconnected(false, null)).link)
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
