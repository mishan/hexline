package org.foggyden.hexline.chat

import android.app.Application
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SecretUnreadable
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.io.IOException

/** The view model's connections and stores, a case at a time, over [ViewModelHarness]. */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class ChatViewModelTest : ViewModelHarness() {
    @Test
    fun theLastServerAskedForIsTheOneConnectedTo() {
        val first = passwordServer("first")
        val second = passwordServer("second")
        saved(first, "pw")
        saved(second, "pw")
        val vm = model()
        settle()
        // Both asked for while the first's secrets are still being read.
        vm.connect(first, null, false)
        vm.connect(second, null, false)
        settle()
        assertEquals(listOf(second.url), opened.map { it.url })
    }

    @Test
    fun aConnectAskedForAgainWhileItsLoginIsOutKeepsTheOneMade() {
        val server = passwordServer("again")
        val vm = model()
        settle()
        vm.connect(server, "pw", true)
        settle()
        vm.connect(server, "pw", true)
        settle()
        land(opened.single(), LOGGED_IN)
        settle()
        assertEquals("the login that landed is remembered", listOf(server), outside { servers.all() })
        assertEquals("pw", outside { servers.password(server) })
    }

    @Test
    fun aLoginThatLandedIsRememberedThoughItsLinkEndsAndAnotherIsMadeBeforeItIs() {
        val server = passwordServer("ended first")
        val next = passwordServer("next")
        val vm = model()
        settle()
        vm.connect(server, "pw", false)
        settle()
        val conn = opened.single()
        land(conn, LOGGED_IN)
        // Landed, and its remember asked for, not made.
        onMain()
        core { conn.sink.deliver(listOf(CoreUpdate.Roster(1u, emptyList(), ""), CoreUpdate.Kicked, CoreUpdate.Closed(false, false))) }
        onMain()
        vm.connect(next, "pw", false)
        settle()
        assertTrue("connected to, so offered again", server in outside { servers.all() })
    }

    @Test
    fun aLoginWhoseLinkEndsBeforeTheModelHearsOfItIsKeptAndLeavesTheNextScreenAlone() {
        val server = passwordServer("heard late")
        val next = passwordServer("next late")
        val vm = model()
        settle()
        vm.connect(server, "pw", false)
        settle()
        val conn = opened.single()
        // The core answers, and runs the link to its end, before the main thread hears of it.
        land(conn, LOGGED_IN.copy(outcome = "linked"))
        core { conn.sink.deliver(listOf(CoreUpdate.Roster(1u, emptyList(), ""), CoreUpdate.Closed(false, true))) }
        vm.connect(next, "pw", false)
        vm.connect(server, "pw", false)
        settle()
        assertTrue("connected to, so offered again", server in outside { servers.all() })
        val shown = vm.chat.value
        assertEquals(
            "the next login's screen",
            listOf(Link.Connecting, false),
            listOf(shown.link, shown.entries.any { it is Entry.SignedIn }),
        )
    }

    @Test
    fun aSessionResumedWithIsKeptUntilTheCoreHasOneOfItsOwn() {
        for (goes in listOf(false, true)) {
            fresh()
            val server = passwordServer("resumed $goes")
            saved(server, "pw", SESSION)
            model()
            settle()
            val conn = opened.single()
            assertArrayEquals(SESSION, conn.resumedWith)
            land(conn, LOGGED_IN.copy(resumed = true))
            settle()
            if (goes) {
                // The screen goes before the core's first batch.
                owner.clear()
                settle()
            }
            assertArrayEquals("goes $goes: kept while the core has none", SESSION, outside { servers.session(server) })
            if (!goes) {
                live(conn)
                settle()
                assertArrayEquals("the core's, once it has one", conn.session, outside { servers.session(server) })
            }
        }
    }

    /** When, against a connect's steps, a forget or a delete is asked for. */
    private enum class When { SecretsRead, DeviceRead, LoginOut, Landed }

    @Test
    fun aForgetOrADeleteAskedForDuringAConnectLeavesNothingOfIt() {
        for (by in listOf("forget", "delete")) {
            for (at in When.entries) {
                fresh()
                val label = "$by at $at"
                val server = identityServer(label)
                keepIdentity()
                // Saved, so its secrets are read; with no session, so the launch resumes nothing.
                if (at == When.SecretsRead) saved(server)
                val vm = model()
                settle()
                vm.connect(server, null, false)
                when (at) {
                    When.SecretsRead -> assertTrue("$label: still reading", opened.isEmpty())
                    When.DeviceRead -> {
                        // Past the link flag, at the device's read.
                        onDisk()
                        onMain()
                        assertEquals("$label: opened", 1, opened.size)
                        assertNull("$label: not yet proved", opened.single().proved)
                    }
                    When.LoginOut -> settle()
                    When.Landed -> {
                        settle()
                        land(opened.single(), identityLoggedIn())
                        // Its remember asked for, not made.
                        onMain()
                    }
                }
                val conn = opened.singleOrNull()
                if (by == "forget") vm.forget(server) else vm.deleteIdentity(FINGERPRINT)
                settle()
                // The core answers the login it was hung up on: closed.
                if (at == When.LoginOut) {
                    land(conn!!, identityLoggedIn())
                    settle()
                }
                if (at == When.SecretsRead || at == When.DeviceRead) assertNull("$label: no seed reaches the core", conn?.proved)
                if (at == When.SecretsRead) assertTrue("$label: nothing opened", opened.isEmpty())
                conn?.let { assertEquals("$label: logged out", true, it.hungUp) }
                assertEquals("$label: shown nothing of it", Link.Idle, vm.chat.value.link)
                if (by == "delete" && at == When.SecretsRead) {
                    assertEquals("$label: a server saved before stays as it was", listOf(server), outside { servers.all() })
                } else {
                    assertTrue("$label: not remembered", server !in outside { servers.all() })
                }
                assertNull("$label: no session kept", outside { servers.session(server) })
                if (by == "delete") assertTrue("$label: the identity goes", !kept())
            }
        }
    }

    @Test
    fun aResumeAtLaunchIsMadeUnlessItsServerOrIdentityGoesWhileItIsRead() {
        for (by in listOf(null, "forget", "delete")) {
            fresh()
            val server = identityServer("launch $by")
            keepIdentity()
            saved(server, session = SESSION)
            // The launch's read is asked for, not made.
            val vm = model()
            when (by) {
                "forget" -> vm.forget(server)
                "delete" -> vm.deleteIdentity(FINGERPRINT)
            }
            settle()
            if (by == null) {
                assertArrayEquals("resumed", SESSION, opened.single().resumedWith)
            } else {
                assertTrue("$by: no connection made", opened.isEmpty())
            }
        }
    }

    @Test
    fun aServersRefusalIsKeptForItsDeviceUnlessForgottenOrDeletedFirst() {
        data class Case(
            val name: String,
            val code: String,
            val lapse: Boolean,
            val before: String?,
            val kept: Boolean,
        )
        val cases =
            listOf(
                Case("refused at login", "revoked", lapse = false, before = null, kept = true),
                Case("refused after a lapse", "rotated", lapse = true, before = null, kept = true),
                Case("refused as busy", "rate_limited", lapse = false, before = null, kept = false),
                Case("refused once forgotten", "revoked", lapse = false, before = "forget", kept = false),
                Case("refused once deleted", "revoked", lapse = false, before = "delete", kept = false),
                Case("refused after a lapse once forgotten", "rotated", lapse = true, before = "forget", kept = false),
                Case("refused after a lapse once deleted", "rotated", lapse = true, before = "delete", kept = false),
            )
        val found = mutableMapOf<String, String?>()
        for (c in cases) {
            fresh()
            val server = identityServer(c.name)
            keepIdentity()
            val device = device()
            val vm = model()
            settle()
            vm.connect(server, null, false)
            settle()
            val conn = opened.single()
            if (c.lapse) {
                land(conn, identityLoggedIn())
                live(conn)
                settle()
            }
            when (c.before) {
                "forget" -> vm.forget(server)
                "delete" -> vm.deleteIdentity(FINGERPRINT)
            }
            if (c.lapse) {
                // A login after a lapse refused: the core's last batch.
                core { conn.sink.deliver(listOf(CoreUpdate.Refused(c.code), CoreUpdate.Closed(false, false))) }
            } else {
                refuse(conn, CoreException.Refused(c.code, ""))
            }
            settle()
            found[c.name] = outside { servers.refused(server, device) }
        }
        assertEquals(cases.associate { it.name to it.code.takeIf { _ -> it.kept } }, found)
    }

    @Test
    fun aRefusedLoginLetGoOfClearsNothingANewerLoginKept() {
        val server = passwordServer("newer")
        val vm = model()
        settle()
        vm.connect(server, "old", true)
        settle()
        val old = opened.single()
        vm.forget(server)
        settle()
        vm.connect(server, "new", true)
        settle()
        val newer = opened.last()
        land(newer, LOGGED_IN)
        live(newer)
        settle()
        // Its server had answered before the hang-up reached it.
        refuse(old, CoreException.Refused("login_failed", ""))
        settle()
        assertEquals("new", outside { servers.password(server) })
        assertArrayEquals(newer.session, outside { servers.session(server) })
    }

    @Test
    fun whatIsAskedForAsTheScreenGoesIsStillMade() {
        val made = mutableMapOf<String, Boolean>()
        for (act in listOf("forget", "delete", "remember", "save")) {
            fresh()
            val server = identityServer("leaving $act")
            keepIdentity()
            if (act == "forget") saved(server)
            val vm = model()
            settle()
            when (act) {
                "forget" -> vm.forget(server)
                "delete" -> vm.deleteIdentity(FINGERPRINT)
                else -> {
                    vm.connect(server, null, false)
                    settle()
                    val conn = opened.single()
                    land(conn, identityLoggedIn())
                    // Landed, and its remember asked for, not made.
                    onMain()
                    if (act == "save") {
                        live(conn)
                        settle()
                        // The core's session as the screen goes is newer than the one kept.
                        conn.session = LATER
                    }
                }
            }
            owner.clear()
            onDisk()
            made[act] =
                outside {
                    when (act) {
                        "forget" -> server !in servers.all()
                        "delete" -> identities.list().isEmpty()
                        "remember" -> server in servers.all()
                        else -> servers.session(server)?.contentEquals(LATER) == true
                    }
                }
        }
        assertEquals(made.keys.associateWith { true }, made)
    }

    @Test
    fun anIdentityOutsideItsTimeOrRefusedHereIsNeitherSignedInWithNorResumed() {
        data class Case(
            val name: String,
            val at: Long,
            val refused: String?,
            val why: Why,
        )
        val cases =
            listOf(
                Case("expired", EXPIRES + PAST_SKEW, null, Why.CertExpired),
                Case("not yet valid", ISSUED - PAST_SKEW, null, Why.CertNotYetValid),
                Case("refused here", ISSUED + DAY, "revoked", Why.Revoked),
            )
        val signedIn = mutableListOf<String>()
        for (c in cases) {
            for (resume in listOf(false, true)) {
                fresh()
                val label = "${c.name}, ${if (resume) "resumed at launch" else "connected"}"
                val server = identityServer(label)
                keepIdentity()
                c.refused?.let { code -> outside { servers.markRefused(server, device(), code) } }
                if (resume) saved(server, session = SESSION)
                now = c.at
                val vm = model()
                settle()
                if (!resume) {
                    vm.connect(server, null, false)
                    settle()
                }
                if (opened.single().proved != null || vm.chat.value.link != Link.Ended(c.why)) signedIn += label
            }
        }
        assertEquals(emptyList<String>(), signedIn)
    }

    @Test
    fun aSecretTheKeystoreWillNotOpenIsToldOrDropped() {
        data class Case(
            val name: String,
            val secret: String,
            val fails: () -> Exception,
            val resume: Boolean,
            val why: Why?,
        )
        val locked = { SecretUnavailable("seed", IOException("locked")) }
        val cases =
            listOf(
                Case("a locked seed, connecting", "device-", locked, resume = false, why = Why.KeyLocked),
                Case("a locked seed, resuming at launch", "device-", locked, resume = true, why = Why.KeyLocked),
                Case("an unreadable seed", "device-", { SecretUnreadable("seed") }, resume = false, why = Why.NoIdentity),
                Case("an unreadable session", "session-", { SecretUnreadable("session") }, resume = true, why = null),
                Case("an unreadable password", "password-", { SecretUnreadable("password") }, resume = false, why = null),
            )
        val wrong = mutableListOf<String>()
        for (c in cases) {
            fresh()
            val server = if (c.secret == "password-") passwordServer(c.name) else identityServer(c.name)
            keepIdentity()
            saved(server, "pw".takeIf { c.secret == "password-" }, SESSION.takeIf { c.resume })
            secrets.fails[c.secret] = c.fails
            val vm = model()
            settle()
            if (opened.isEmpty()) {
                vm.connect(server, null, false)
                settle()
            }
            val conn = opened.single()
            secrets.fails.clear()
            val right =
                when (c.secret) {
                    "device-" ->
                        conn.proved == null &&
                            vm.chat.value.link == Link.Ended(c.why!!) &&
                            kept() == (c.why == Why.KeyLocked)
                    // Read as none, and forgotten.
                    "session-" -> conn.resumedWith == null && outside { servers.session(server) } == null
                    else -> conn.password == null && outside { servers.password(server) } == null
                }
            if (!right) wrong += c.name
        }
        assertEquals(emptyList<String>(), wrong)
    }

    @Test
    fun aSessionNothingWillResumeIsForgottenAndNotTakenUpAtTheNextLaunch() {
        val closed = { replaced: Boolean -> CoreUpdate.Closed(false, replaced) }
        val cases =
            listOf<Pair<String, List<CoreUpdate>?>>(
                "kicked" to listOf(CoreUpdate.Kicked, closed(false)),
                "replaced" to listOf(closed(true)),
                "refused after a lapse" to listOf(CoreUpdate.Refused("session_expired"), closed(false)),
                // No batch: the server said at login that the session would not survive.
                "not resumable from its login" to null,
                "a new login after a lapse that will not survive one" to
                    listOf(CoreUpdate.Reconnected(true, LOGGED_IN.copy(canResume = false)), CoreUpdate.Roster(1u, emptyList(), "")),
            )
        val resumed = mutableListOf<String>()
        for ((name, last) in cases) {
            // The main thread told of it before the screen goes, or not yet.
            for (heard in listOf(true, false)) {
                if (last == null && !heard) continue
                fresh()
                val label = "$name${if (heard) "" else ", the screen going first"}"
                val server = passwordServer(label)
                saved(server, "pw", SESSION)
                model()
                settle()
                val conn = opened.single()
                land(conn, LOGGED_IN.copy(canResume = last != null, resumed = true))
                settle()
                if (last != null) {
                    live(conn)
                    settle()
                    over(conn, last)
                    if (heard) settle()
                }
                owner.clear()
                settle()
                if (outside { servers.session(server) } != null) resumed += "$label: a session kept"
                model()
                settle()
                if (opened.size > 1) resumed += "$label: taken up at launch"
            }
        }
        assertEquals(emptyList<String>(), resumed)
    }

    @Test
    fun aLinksSessionIsSavedOnceTheCoreHasOne() {
        val found = mutableMapOf<String, String?>()
        for (how in listOf("logged in", "logged in again")) {
            fresh()
            val server = passwordServer(how)
            val vm = model()
            settle()
            vm.connect(server, "pw", false)
            settle()
            val conn = opened.single()
            land(conn, LOGGED_IN)
            // Nothing after either session is told: the link stays quiet.
            live(conn)
            settle()
            if (how == "logged in again") {
                // A new login made by the core, its session kept after its first batch.
                core { conn.sink.deliver(listOf(CoreUpdate.Reconnected(false, LOGGED_IN))) }
                onMain()
                sessionKept(conn, ROTATED)
                settle()
            }
            found[how] = outside { servers.session(server) }?.let(::String)
        }
        assertEquals(
            mapOf("logged in" to "session of ws://logged-in.example/ng", "logged in again" to String(ROTATED)),
            found,
        )
    }

    @Test
    fun deletingTheIdentityInUseLogsOutAndForgetsWhatEveryServerKeptForIt() {
        val server = identityServer("in use")
        val other = identityServer("other")
        keepIdentity()
        val device = device()
        val vm = model()
        settle()
        // Kept after the launch, which would resume it.
        saved(other, session = SESSION)
        outside { servers.markRefused(other, device, "revoked") }
        vm.connect(server, null, false)
        settle()
        val conn = opened.single()
        land(conn, identityLoggedIn())
        live(conn)
        settle()
        vm.deleteIdentity(FINGERPRINT)
        assertEquals("logged out at once", true, conn.hungUp)
        settle()
        assertTrue(!kept())
        for (s in listOf(server, other)) assertNull("${s.url}'s session", outside { servers.session(s) })
        assertTrue("its refusals", outside { servers.refusals() }.isEmpty())
    }

    @Test
    fun aDeviceEnrolledIsKeptOnlyOnceThePersonHasSeenWhoseItIs() {
        for (then in listOf("keep", "discard", "cancel while waiting")) {
            fresh()
            val vm = model()
            settle()
            vm.startEnroll(null)
            settle()
            assertEquals(then, "ready $DEVICE", shownAs(vm))
            val e = enrollments.single()
            assertNull("$then: a new device", e.renewing)
            vm.requestEnroll(gen(vm), "hl.example", "K7PM-4XWE", "Hexline")
            settle()
            assertEquals(then, Triple("hl.example", "K7PM-4XWE", "Hexline"), e.asked)
            assertEquals(then, "waiting $DEVICE", shownAs(vm))
            if (then == "cancel while waiting") {
                vm.discardEnroll()
                settle()
                assertTrue("$then: the wait ends and the key goes", e.canceled && e.closed)
                assertTrue(then, stored() == null)
                continue
            }
            core { e.answer.complete(ENROLLED) }
            settle()
            val answered = vm.enrollment.value as Enrolling.Answered
            assertEquals(
                then,
                listOf(DEVICE, "Fixture", FINGERPRINT, EXPIRES.toULong(), false, null),
                listOf(answered.device, answered.name, answered.fingerprint, answered.info.expires, answered.namesake, answered.replaces),
            )
            assertTrue("$then: nothing kept before the person says", stored() == null)
            if (then == "keep") confirm(vm) else vm.discardEnroll()
            settle()
            assertTrue("$then: the key is let go of", e.closed)
            if (then == "keep") {
                val kept = stored()!!
                // The card's name is the identity's word for itself, not a registrar's handle.
                assertEquals(listOf(FINGERPRINT, null, "hl.example"), listOf(kept.fingerprint, kept.handle, kept.mailbox))
                assertArrayEquals(SEED, outside { identities.device(FINGERPRINT)?.second })
                assertEquals("done $FINGERPRINT", shownAs(vm))
            } else {
                assertNull(then, stored())
            }
        }
    }

    @Test
    fun aRenewalByCodeIsTheDeviceKeptWhileInItsTimeAndANewOneOnceExpired() {
        for (expired in listOf(false, true)) {
            fresh()
            keepIdentity("hl.example")
            now = if (expired) EXPIRES + PAST_SKEW else ISSUED + DAY
            val vm = model()
            settle()
            vm.startEnroll(FINGERPRINT)
            settle()
            val e = enrollments.single()
            if (expired) {
                assertNull("a lapsed certificate enrolls afresh", e.renewing)
            } else {
                assertArrayEquals(SEED, e.renewing!!.first)
                assertArrayEquals(CERT, e.renewing.second)
            }
            assertEquals("expired $expired: as the same identity's", FINGERPRINT, e.expecting)
        }
    }

    @Test
    fun anEnrollmentAskedForAgainWhileTheFirstReadsItsDeviceLetsTheFirstGo() {
        keepIdentity("hl.example")
        val vm = model()
        settle()
        vm.startEnroll(FINGERPRINT)
        // Its device's read is queued, not made.
        onMain()
        vm.startEnroll(FINGERPRINT)
        settle()
        assertEquals(2, enrollments.size)
        assertTrue("the first is let go of", enrollments[0].closed)
        assertTrue("the second is the one shown", !enrollments[1].closed)
        assertEquals("ready $DEVICE", shownAs(vm))
    }

    @Test
    fun anAnswerForAnIdentityOnThePhoneSaysWhatItReplaces() {
        for (held in listOf(false, true)) {
            fresh()
            if (held) keepIdentity("hl.example")
            val vm = model()
            settle()
            vm.startEnroll(null)
            settle()
            vm.requestEnroll(gen(vm), "hl.example", "K7PM-4XWE", "Hexline")
            settle()
            core { enrollments.single().answer.complete(ENROLLED) }
            settle()
            val answered = vm.enrollment.value as Enrolling.Answered
            assertEquals("held $held", held, answered.replaces != null)
        }
    }

    @Test
    fun anAnswerThePhoneCouldNotKeepAsksToStartAgain() {
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        vm.requestEnroll(gen(vm), "hl.example", "K7PM-4XWE", "Hexline")
        settle()
        val e = enrollments.single()
        core { e.answer.complete(ENROLLED) }
        settle()
        secrets.putFails = { SecretUnavailable("seed", IOException("locked")) }
        confirm(vm)
        settle()
        assertEquals("failed  AnswerNotKept", shownAs(vm))
        assertTrue("its device is gone", e.closed)
        secrets.putFails = null
        vm.startEnroll(null)
        settle()
        assertEquals("a new device to ask with", "ready $DEVICE", shownAs(vm))
        assertEquals(2, enrollments.size)
    }

    @Test
    fun aSaveConfirmedThenLeftForAnotherEnrollmentDoesNotEndTheOther() {
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        vm.requestEnroll(gen(vm), "hl.example", "K7PM-4XWE", "Hexline")
        settle()
        core { enrollments.single().answer.complete(ENROLLED) }
        settle()
        confirm(vm)
        assertEquals("nothing left to discard", "saving Fixture", shownAs(vm))
        // Its save still queued, another begun.
        vm.discardEnroll()
        vm.startEnroll(null)
        settle()
        assertEquals("the second's screen", "ready $DEVICE", shownAs(vm))
        assertTrue("the second still open", !enrollments[1].closed)
        assertEquals("the first kept, as the person said", FINGERPRINT, stored()?.fingerprint)
    }

    @Test
    fun aQuietRenewalIsOfTheRecordAsItIsWhenItsDeviceIsRead() {
        keepIdentity("old.example")
        now = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        model()
        // The launch's first read, then the renewal's list of what is due.
        onMain()
        onDisk()
        onMain()
        onDisk()
        // Enrolled again through another mailbox before its device is read.
        keepIdentity("new.example")
        settle()
        assertEquals("new.example", enrollments.single().asked?.first)
    }

    @Test
    fun aDueDeviceIsRenewedQuietlyOnceADayWhereAHolderStandsBy() {
        val due = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        for (answer in listOf("renewed", "no holder", "unreachable", "left while waiting", "not due")) {
            fresh()
            keepIdentity("hl.example")
            // Tried long ago, and found no holder then.
            outside { identities.renewTried(FINGERPRINT, CERT, 1, true) }
            now = if (answer == "not due") ISSUED + DAY else due
            model()
            settle()
            if (answer == "not due") {
                assertTrue(answer, enrollments.isEmpty())
                continue
            }
            val e = enrollments.single()
            assertEquals("$answer: written before the holder is asked", due, triedWhenAsked)
            assertArrayEquals("$answer: the device it has", SEED, e.renewing!!.first)
            assertEquals(answer, Triple("hl.example", null, "Hexline"), e.asked)
            // The holder takes its time: what is noted is when it ended.
            now += HOUR
            when (answer) {
                "renewed" -> core { e.answer.complete(enrolled(RENEWED)) }
                "no holder" -> core { e.answer.completeExceptionally(CoreException.Refused("no_holder", "")) }
                "left while waiting" -> owner.clear()
                else -> {
                    // Unreachable before its request reached the mailbox.
                    e.posted = false
                    core { e.answer.completeExceptionally(CoreException.Connect("offline")) }
                }
            }
            settle()
            assertTrue("$answer: let go of", e.closed)
            val kept = stored()!!
            when (answer) {
                "renewed" -> {
                    assertEquals(answer, listOf(0L, false, "hl.example"), listOf(kept.renewTried, kept.noHolder, kept.mailbox))
                    assertArrayEquals("$answer: the new certificate kept", RENEWED, kept.cert)
                }
                "no holder" -> assertEquals(answer, listOf(due + HOUR, true), listOf(kept.renewTried, kept.noHolder))
                "left while waiting" ->
                    assertEquals(
                        "$answer: a holder asked counts, from when it was asked",
                        listOf(due, false),
                        listOf(kept.renewTried, kept.noHolder),
                    )
                else -> assertEquals("$answer: not counted", listOf(1L, true), listOf(kept.renewTried, kept.noHolder))
            }
            if (answer == "renewed") continue
            // The app again, the same day, and the next.
            if (answer != "left while waiting") owner.clear()
            settle()
            model()
            settle()
            assertEquals("$answer: asked again the same day", if (answer == "unreachable") 2 else 1, enrollments.size)
            owner.clear()
            settle()
            now += DAY
            model()
            settle()
            assertEquals("$answer: and the next", if (answer == "unreachable") 3 else 2, enrollments.size)
        }
    }

    @Test
    fun aQuietRenewalsTryIsNotedAsOfWhenItsHolderIsAsked() {
        val due = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        keepIdentity("hl.example")
        now = due
        model()
        // The try written, and the holder not yet asked: the process frozen there for a month.
        var rounds = 0
        while (stored()?.renewTried != due) {
            assertTrue("the try never noted as of $due", ++rounds <= SETTLE)
            onMain()
            disk.step()
        }
        now += 30 * DAY
        settle()
        assertEquals("a later run would ask again a day after this", now, triedWhenAsked)
    }

    @Test
    fun aQuietRenewalAnsweredForAnotherIdentityKeepsNothing() {
        keepIdentity("hl.example")
        now = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        model()
        settle()
        core { enrollments.single().answer.complete(enrolled(RENEWED, fingerprint = "someone-else")) }
        settle()
        assertArrayEquals(CERT, stored()!!.cert)
    }

    @Test
    fun aRenewalByCodeKeepsTheNewCertificateWithTheHandleItHad() {
        keepIdentity("old.example")
        val vm = model()
        settle()
        vm.startEnroll(FINGERPRINT)
        settle()
        vm.requestEnroll(gen(vm), "new.example", "K7PM-4XWE", "Hexline")
        settle()
        core { enrollments.single().answer.complete(enrolled(RENEWED)) }
        settle()
        confirm(vm)
        settle()
        val kept = stored()!!
        assertArrayEquals(RENEWED, kept.cert)
        assertEquals(listOf("alice@example", "new.example"), listOf(kept.handle, kept.mailbox))
    }

    @Test
    fun anAnswerForANewIdentityByANameThePhoneHoldsSaysSo() {
        keepIdentity("hl.example")
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        vm.requestEnroll(gen(vm), "hl.example", "K7PM-4XWE", "Hexline")
        settle()
        core { enrollments.single().answer.complete(enrolled(CERT, fingerprint = "another")) }
        settle()
        val answered = vm.enrollment.value as Enrolling.Answered
        assertEquals(listOf(true, null), listOf(answered.namesake, answered.replaces))
    }

    @Test
    fun aRenewalWhoseDeviceCannotBeReadIsANewDeviceHeldToItsIdentity() {
        for (device in listOf("gone", "unreadable")) {
            fresh()
            if (device == "unreadable") {
                keepIdentity("hl.example")
                secrets.fails["device-"] = { SecretUnreadable("seed", IOException("bad")) }
            }
            val vm = model()
            settle()
            vm.startEnroll(FINGERPRINT)
            settle()
            val e = enrollments.single()
            assertEquals(device, listOf(null, FINGERPRINT), listOf(e.renewing, e.expecting))
            vm.requestEnroll(gen(vm), "hl.example", "K7PM-4XWE", "Hexline")
            settle()
            core { e.answer.complete(enrolled(CERT, fingerprint = "another")) }
            settle()
            assertEquals(device, "failed $DEVICE NotForThisPhone", shownAs(vm))
        }
    }

    @Test
    fun aRunTakesOneRequestAndKeepsOnlyTheAnswerItShowed() {
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        val first = gen(vm)
        vm.requestEnroll(first, "hl.example", "K7PM-4XWE", "Hexline")
        vm.requestEnroll(first, "other.example", "K7PM-4XWE", "Hexline")
        settle()
        val e = enrollments.single()
        assertEquals("asked once", "hl.example", e.asked?.first)
        core { e.answer.complete(ENROLLED) }
        settle()
        vm.confirmEnroll(first, "someone-else")
        vm.confirmEnroll(first - 1, FINGERPRINT)
        settle()
        assertNull("neither the answer shown nor this run's", stored())
        assertTrue(vm.enrollment.value is Enrolling.Answered)
    }

    @Test
    fun signingInLeavesEnrollingAndItsDeviceGoes() {
        val server = passwordServer("signing in")
        val vm = model()
        settle()
        vm.startEnroll(null)
        settle()
        vm.connect(server, "pw", false)
        settle()
        land(opened.single(), LOGGED_IN)
        live(opened.single())
        settle()
        assertTrue("its key wiped", enrollments.single().closed)
        assertEquals(Enrolling.Idle, vm.enrollment.value)
    }

    @Test
    fun aRenewalsTryTheStoreCannotWriteIsLostAndNothingElse() {
        keepIdentity("hl.example")
        now = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        val dir = File(app.filesDir, "identities-$cases")
        try {
            // Nothing can be written there now.
            dir.setWritable(false)
            model()
            settle()
            val e = enrollments.single()
            core { e.answer.completeExceptionally(CoreException.Refused("no_holder", "")) }
            settle()
            assertTrue("the holder was still asked", e.asked != null)
        } finally {
            dir.setWritable(true)
        }
    }

    @Test
    fun aRenewalAnsweredAfterItsIdentityIsDeletedKeepsNothing() {
        keepIdentity("hl.example")
        now = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY
        val vm = model()
        settle()
        val e = enrollments.single()
        vm.deleteIdentity(FINGERPRINT)
        settle()
        core { e.answer.complete(ENROLLED) }
        settle()
        assertNull(stored())
        assertNull(outside { identities.device(FINGERPRINT) })
    }

    @Test
    fun aWaitBegunBeforeAProcessDiesNeverEndsAfterIt() {
        for ((name, queue, drop) in listOf(
            Triple("main", main, { main.queue.drop() }),
            Triple("store", disk, { disk.drop() }),
        )) {
            var woke = false
            CoroutineScope(queue).launch {
                delay(1_000)
                woke = true
            }
            // Only as far as the wait: its time is not moved on.
            while (main.queue.step() || disk.step()) continue
            drop()
            settle()
            assertFalse("$name: a wait begun before the process died ended after it", woke)
        }
    }
}
