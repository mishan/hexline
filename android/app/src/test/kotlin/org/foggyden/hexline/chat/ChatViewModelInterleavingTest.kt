package org.foggyden.hexline.chat

import android.app.Application
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelStore
import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.Enrolled
import org.foggyden.hexline.core.LoginInfo
import org.foggyden.hexline.core.UpdateSink
import org.foggyden.hexline.core.certForDevice
import org.foggyden.hexline.core.renewalDue
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.random.Random

/**
 * The view model driven by a seeded stream of everything that can happen
 * to it, in any order: a task on the main thread or the store queue, the
 * core answering a login, a batch or an enrollment, the person's taps, the
 * clock moving, the screen going and the process dying. After every step
 * what the model promises is checked; a failure names its seed and the
 * steps that led to it, and HEXLINE_SEED with HEXLINE_SEEDS=1 replays it
 * (HEXLINE_STEPS steps each).
 *
 * The fakes refuse what the core would, so no stream asks of the model what
 * the core never could. Tasks run one at a time, on one thread: this orders
 * the model's steps every way they can be ordered, and is no proof that it
 * is safe across threads. It does not reach history and the filling of a
 * gap, restoring from a registrar, sending, or a change of network.
 */
@RunWith(RobolectricTestRunner::class)
@Config(application = Application::class)
class ChatViewModelInterleavingTest : ViewModelHarness() {
    private lateinit var run: Run

    override fun connection(
        url: String,
        sink: UpdateSink,
    ): FakeConnection = run.Conn(url, sink)

    override fun enrollment(
        renewing: Pair<ByteArray, ByteArray>?,
        expecting: String?,
    ): FakeEnrollment = run.made(renewing, expecting)

    @Test
    fun noOrderOfActsAndAnswersBreaksWhatTheModelPromises() {
        val count = System.getenv("HEXLINE_SEEDS")?.toIntOrNull() ?: SEEDS
        val from = System.getenv("HEXLINE_SEED")?.toLongOrNull() ?: 1L
        for (seed in from until from + count) {
            run = Run(seed)
            run.go()
        }
    }

    /** One seed's stream, and what it has seen so far to check against. */
    private inner class Run(
        private val seed: Long,
    ) {
        private val rnd = Random(seed)
        private val log = mutableListOf<String>()
        private var step = 0

        /** A process: what an older one left running never runs again. */
        private var epoch = 0
        private lateinit var vm: ChatViewModel

        private val p1 = passwordServer("one $seed")
        private val p2 = passwordServer("two $seed")
        private val i1 = identityServer("id $seed")
        private val i3 = Server("ws://other-$seed.example/ng", null, SignIn.Identity(FP3))
        private val all = listOf(p1, p2, i1, i3)

        /** Certificates a stored identity may hold: seeded, confirmed, or a quiet renewal's of its own identity. */
        private val allowed = mutableSetOf<String>()

        /** Answers not yet given, each given once so what was kept says which it was. */
        private val pool = (MINTED + listOf(RENEWED)).toMutableList()
        private var otherGiven = false

        /** By server, the step of the last word that ends its session, and of the last session the core kept. */
        private val ended = mutableMapOf<String, Int>()
        private val keptAt = mutableMapOf<String, Int>()

        /**
         * By server, the step the connection whose login last landed began
         * (a forget after that lets go of it), and of what lets one go unremembered.
         */
        private val landedAt = mutableMapOf<String, Int>()
        private val forgotAt = mutableMapOf<String, Int>()
        private var diedAt = -1

        /** The last step nothing was left to run after: what was asked before it has been made. */
        private var quietAt = -1

        /**
         * What the stores are to show, in the order it was asked for: a
         * server landed, forgotten or refused, an identity deleted or
         * confirmed, a password refused, a refusal tried again.
         */
        private val events = mutableListOf<Ev>()

        /** Steps whose store work may have died with its process unmade. */
        private val lost = mutableListOf<IntRange>()

        private fun sure(at: Int) = lost.none { at in it }

        /** Sessions the server has refused or ended: no login resumes one again. */
        private val dead = mutableSetOf<String>()

        /** This process's starts, by what each would renew. */
        private val starts = mutableMapOf<String?, Int>()

        val conns get() = opened.filterIsInstance<Conn>()
        val enrs get() = enrollments.filterIsInstance<Enr>()

        inner class Conn(
            url: String,
            sink: UpdateSink,
        ) : FakeConnection(url, sink) {
            val epoch = this@Run.epoch
            val server = all.single { it.url == url }
            val created = step

            /** Answered by the core: its link runs from then, whatever the model has made of it. */
            var landed = false
            var rostered = false
            var over = false
            var noResume = false
            var seen = false
        }

        /** Told as its holder is asked: set once the enrollment exists. */
        private inner class Hook {
            var of: Enr? = null
        }

        inner class Enr(
            renewing: Pair<ByteArray, ByteArray>?,
            expecting: String?,
            val quiet: Boolean,
            hook: Hook,
        ) : FakeEnrollment(renewing, expecting, { asked(hook.of!!) }) {
            val epoch = this@Run.epoch
            var askedAt: Long? = null

            /** The core's own refusals: an answer out of its time, and a renewal's from another identity or due again. */
            override fun refuses(got: Enrolled): CoreException? {
                if (now + SKEW < got.info.issued.toLong() || now > got.info.expires.toLong() + SKEW) {
                    return CoreException.Refused("cert_expired", "")
                }
                val prev = renewing?.second ?: return null
                if (identityOf(prev) != got.fingerprint) return CoreException.Refused("wrong_identity", "")
                if (renewalDue(got.info.issued, got.info.expires, now.toULong())) return CoreException.Refused("short_renewal", "")
                return null
            }
        }

        fun made(
            renewing: Pair<ByteArray, ByteArray>?,
            expecting: String?,
        ): Enr {
            // Asked for by the renewal with nobody typing, or by the enroll screen.
            val quiet = Thread.currentThread().stackTrace.any { it.className.startsWith(QuietRenewal::class.java.name) }
            val hook = Hook()
            val made = Enr(renewing, expecting, quiet, hook)
            hook.of = made
            if (!quiet && renewing != null && expecting != identityOf(renewing.second)) {
                fail("a renewal by code not held to its identity: expecting $expecting")
            }
            return made
        }

        private fun asked(e: Enr) {
            e.askedAt = now
            if (!e.quiet) return
            val fp = identityOf(e.renewing!!.second)
            val earlier =
                enrs.filter { it !== e && it.quiet && it.posted && it.askedAt != null && identityOf(it.renewing!!.second) == fp }
            // A try is noted up to a minute before its holder is asked.
            earlier.find { now - it.askedAt!! < DAY - NOTED_WITHIN }?.let {
                fail("a holder asked again for $fp within a day: at ${it.askedAt} and $now")
            }
        }

        fun go() {
            fresh()
            now = listOf(ISSUED + DAY, DUE, DUE + DAY).random(rnd)
            if (rnd.nextInt(5) > 0) {
                keepIdentity(if (rnd.nextBoolean()) "hl.example" else null)
                allowed += hexOf(CERT)
            }
            saved(p1, password(p1), session(p1, "seeded").takeIf { rnd.nextBoolean() })
            if (rnd.nextBoolean()) saved(i1, null, session(i1, "seeded").takeIf { rnd.nextBoolean() })
            vm = model()
            check()
            val steps = System.getenv("HEXLINE_STEPS")?.toIntOrNull() ?: STEPS
            while (step < steps) {
                step++
                act()
                check()
            }
            step++
            log += "settle"
            settle()
            check()
        }

        private fun password(s: Server) = "pw-${s.url}"

        private fun session(
            s: Server,
            what: String,
        ) = "${s.url} $what".toByteArray()

        private fun act() {
            repeat(TRIES) {
                val did =
                    when (rnd.nextInt(100)) {
                        in 0 until 22 -> main.queue.step().done("main")
                        in 22 until 42 -> disk.step().done("disk")
                        in 42 until 51 -> login()
                        in 51 until 59 -> batch()
                        in 59 until 66 -> answer()
                        in 66 until 94 -> tap()
                        in 94 until 97 -> clock()
                        in 97 until 99 -> restart()
                        else -> die()
                    }
                if (did != null) {
                    log += "$step: $did"
                    return
                }
            }
            log += "$step: nothing"
        }

        private fun Boolean.done(what: String) = what.takeIf { this }

        private fun login(): String? {
            val c = conns.filter { it.epoch == epoch && it.loginAsked && !it.answer.isCompleted }.randomOrNull(rnd) ?: return null
            val what =
                when (rnd.nextInt(8)) {
                    in 0 until 4 -> {
                        val canResume = rnd.nextInt(7) > 0
                        val resumed = c.resumedWith?.let { hexOf(it) !in dead } == true && rnd.nextInt(5) > 0
                        val identity = (c.server.signIn as? SignIn.Identity)?.fingerprint
                        c.landed = true
                        // The core keeps no session for a login that will not survive a lapse.
                        c.noResume = !canResume
                        core {
                            c.answer.complete(LoginInfo("hxd", emptyList(), canResume, identity, identity?.let { "linked" }, resumed))
                        }
                        // Now and then its link ended by the core before the main thread has heard it landed.
                        val gone = !c.isClosed && rnd.nextInt(4) == 0
                        if (gone) {
                            c.rostered = true
                            end(c, CoreUpdate.Roster(1u, emptyList(), ""), CoreUpdate.Closed(false, true))
                        }
                        "landed${if (canResume) "" else ", not to resume"}${if (resumed) ", resumed" else ""}${if (gone) ", and replaced at once" else ""}"
                    }
                    in 4 until 6 -> {
                        val code =
                            listOf(
                                "revoked",
                                "rotated",
                                "rate_limited",
                                "login_failed",
                                "session_expired",
                                "server_full",
                            ).random(rnd)
                        if (!keepsSession(code)) c.resumedWith?.let { dead += hexOf(it) }
                        core { c.answer.completeExceptionally(CoreException.Refused(code, "")) }
                        "refused $code"
                    }
                    6 -> {
                        core { c.answer.completeExceptionally(CoreException.Connect("offline")) }
                        "unreachable"
                    }
                    else -> {
                        core { c.answer.completeExceptionally(CoreException.Closed()) }
                        "closed"
                    }
                }
            return "login ${c.url}: $what"
        }

        private fun batch(): String? {
            val c =
                conns
                    .filter { it.epoch == epoch && !it.isClosed && !it.over && it.landed }
                    .randomOrNull(rnd) ?: return null
            val url = c.server.url
            val what =
                if (!c.rostered) {
                    c.rostered = true
                    deliver(c, CoreUpdate.Roster(1u, emptyList(), ""))
                    "roster"
                } else {
                    when (rnd.nextInt(7)) {
                        in 0 until 3 -> {
                            if (c.noResume) return null
                            c.session = session(c.server, "kept at $step")
                            keptAt[url] = step
                            deliver(c, CoreUpdate.SessionKept)
                            "session kept"
                        }
                        3 -> end(c, CoreUpdate.Kicked, CoreUpdate.Closed(false, false)).let { "kicked" }
                        4 -> end(c, CoreUpdate.Closed(false, true)).let { "replaced" }
                        5 -> {
                            val code = listOf("revoked", "rotated", "session_expired").random(rnd)
                            if (code != "session_expired" && c.proved != null) {
                                events += Ev(step, "refused", url, code = code, created = c.created)
                            }
                            end(c, CoreUpdate.Refused(code), CoreUpdate.Closed(false, false))
                            "refused after a lapse, $code"
                        }
                        else -> {
                            val canResume = rnd.nextBoolean()
                            val identity = (c.server.signIn as? SignIn.Identity)?.fingerprint
                            if (!canResume) {
                                c.noResume = true
                                listOfNotNull(c.session, c.resumedWith).forEach { dead += hexOf(it) }
                                c.session = null
                                ended[url] = step
                            }
                            deliver(c, CoreUpdate.Reconnected(false, LoginInfo("hxd", emptyList(), canResume, identity, null, false)))
                            "logged in again${if (canResume) "" else ", not to resume"}"
                        }
                    }
                }
            return "batch ${c.url}: $what"
        }

        private fun deliver(
            c: Conn,
            vararg updates: CoreUpdate,
        ) = core { c.sink.deliver(updates.toList()) }

        /** [c]'s last batch: the core keeps no session after it. */
        private fun end(
            c: Conn,
            vararg updates: CoreUpdate,
        ) {
            c.over = true
            listOfNotNull(c.session, c.resumedWith).forEach { dead += hexOf(it) }
            c.session = null
            ended[c.server.url] = step
            deliver(c, *updates)
        }

        private fun answer(): String? {
            val e =
                enrs.filter { it.epoch == epoch && it.asked != null && !it.answer.isCompleted && !it.closed }.randomOrNull(rnd)
                    ?: return null
            val what =
                when (rnd.nextInt(7)) {
                    in 0 until 2 -> {
                        val cert = pool.removeFirstOrNull() ?: return null
                        val got = enrolled(cert, CARD)
                        if (e.quiet && identityOf(e.renewing!!.second) == got.fingerprint) allowed += hexOf(cert)
                        core { e.answer.complete(got) }
                        "certified ${hexOf(cert).takeLast(8)}"
                    }
                    2 -> {
                        if (otherGiven) return null
                        otherGiven = true
                        core { e.answer.complete(enrolled(CERT3, CARD3)) }
                        "certified for another identity"
                    }
                    3 -> fails(e, CoreException.Refused("denied", "not_mine")).let { "denied" }
                    4 -> fails(e, CoreException.Refused("no_holder", "")).let { "no holder" }
                    5 -> {
                        // Unreachable before its request reached the mailbox.
                        e.posted = false
                        fails(e, CoreException.Connect("offline"))
                        "unreachable before it asked"
                    }
                    else -> fails(e, CoreException.Connect("offline")).let { "unreachable after it asked" }
                }
            return "enrollment ${if (e.quiet) "quiet" else "by code"}: $what"
        }

        private fun fails(
            e: Enr,
            why: CoreException,
        ) = core { e.answer.completeExceptionally(why) }

        private fun tap(): String? =
            when (rnd.nextInt(16)) {
                0, 1 -> {
                    val s = listOf(p1, p2).random(rnd)
                    val typed = password(s).takeIf { rnd.nextBoolean() }
                    vm.connect(s, typed, rnd.nextBoolean())
                    "connect ${s.url}${if (typed == null) "" else ", typed"}"
                }
                2, 3 -> {
                    val s = listOf(i1, i3).random(rnd)
                    // Now and then with an account of its own to link.
                    val link = ClassicLogin("alice", password(s)).takeIf { rnd.nextInt(4) == 0 }
                    vm.connect(s, null, false, link)
                    "connect ${s.url}${if (link == null) "" else ", to link"}"
                }
                4 -> {
                    val s = all.random(rnd)
                    val typed = password(s).takeIf { s.signIn == SignIn.Password && rnd.nextBoolean() }
                    vm.connect(s, typed, false)
                    vm.connect(s, typed, false)
                    "connect ${s.url} twice"
                }
                5, 6 -> {
                    val target = listOf(null, FINGERPRINT, FP3).random(rnd)
                    starts.merge(target, 1, Int::plus)
                    vm.startEnroll(target)
                    "start enrolling for $target"
                }
                7, 8 -> {
                    val g = if (rnd.nextInt(4) > 0) gen(vm) else gen(vm) - 1
                    val mailbox = listOf("hl.example", "other.example").random(rnd)
                    vm.requestEnroll(g, mailbox, "K7PM-4XWE", "Hexline")
                    if (rnd.nextInt(4) == 0) vm.requestEnroll(g, mailbox, "K7PM-4XWE", "Hexline")
                    "request run $g at $mailbox"
                }
                9 -> confirmTap()
                10 -> vm.discardEnroll().let { "discard" }
                11 -> {
                    val s = all.random(rnd)
                    forgotAt[s.url] = step
                    ended[s.url] = step
                    events += Ev(step, "forget", s.url)
                    vm.forget(s)
                    "forget ${s.url}"
                }
                12 -> {
                    val fp = listOf(FINGERPRINT, FP3).random(rnd)
                    // Its servers' sessions go, and a login of it not yet remembered is not.
                    for (s in all.filter { it.signIn == SignIn.Identity(fp) }) {
                        ended[s.url] = step
                        forgotAt[s.url] = step
                    }
                    events += Ev(step, "delete", fp = fp)
                    vm.deleteIdentity(fp)
                    "delete $fp"
                }
                13 -> {
                    events += Ev(step, "try", i1.url)
                    vm.tryAgain(i1, FINGERPRINT)
                    "try again"
                }
                14 -> {
                    val fg = rnd.nextBoolean()
                    process.lifecycle.handleLifecycleEvent(if (fg) Lifecycle.Event.ON_START else Lifecycle.Event.ON_STOP)
                    if (fg) "foreground" else "background"
                }
                else -> {
                    // Leaving the server it is on: its session goes.
                    conns.lastOrNull { it.epoch == epoch && !it.isClosed }?.let { ended[it.server.url] = step }
                    vm.disconnect()
                    "disconnect"
                }
            }

        private fun confirmTap(): String {
            val shown = vm.enrollment.value as? Enrolling.Answered
            if (shown == null) {
                vm.confirmEnroll(gen(vm), FINGERPRINT)
                return "confirm nothing shown"
            }
            return when (rnd.nextInt(4)) {
                0 -> {
                    vm.confirmEnroll(shown.gen - 1, shown.fingerprint)
                    "confirm an older run"
                }
                1 -> {
                    vm.confirmEnroll(shown.gen, "someone-else")
                    "confirm another identity than shown"
                }
                else -> {
                    allowed += hexOf(CERTS.getValue(shown.fingerprint to shown.info.issued))
                    events += Ev(step, "confirm", fp = shown.fingerprint)
                    vm.confirmEnroll(shown.gen, shown.fingerprint)
                    "confirm what was shown"
                }
            }
        }

        private fun clock(): String {
            val by = listOf(HOUR, DAY, DAY, 30 * DAY).random(rnd)
            now += by
            return "clock +${by / HOUR}h"
        }

        private fun restart(): String {
            owner.clear()
            vm = model()
            return "screen gone, and back"
        }

        /** The process killed: nothing it was doing runs again, and a new one starts on what it wrote. */
        private fun die(): String {
            main.queue.drop()
            disk.drop()
            epoch++
            diedAt = step
            lost += (quietAt + 1)..step
            // A clear still waiting to be made dies with the process: where the
            // session it was to clear is still there, nothing ended it.
            for (s in all) if ((ended[s.url] ?: -1) > quietAt && outside { servers.session(s) } != null) ended -= s.url
            starts.clear()
            forgetDeadProcess()
            owner = ViewModelStore()
            process = Process()
            stores = Stores(cases, stores.secrets)
            vm = model()
            return "process killed, and started again"
        }

        private fun check() {
            uncaught.firstOrNull()?.let {
                uncaught.clear()
                fail("thrown on the model's threads: $it")
            }
            for (c in conns) {
                c.password?.let { if (it != password(c.server)) fail("${c.url} sent another server's password") }
                c.linked?.let { if (it.password != password(c.server)) fail("${c.url} sent another server's password to link") }
                val got = c.outcome
                if (c.seen || got == null || c.epoch != epoch) continue
                c.seen = true
                val url = c.server.url
                got.onSuccess {
                    landedAt[url] = c.created
                    events += Ev(step, "landed", url, created = c.created)
                    if (!it.canResume) ended[url] = step
                }
                got.onFailure {
                    val code = (it as? CoreException.Refused)?.code
                    if (code != null && !keepsSession(code) && c.resumedWith != null) ended[url] = step
                    if (code == "login_failed") events += Ev(step, "pwfail", url)
                    if ((code == "revoked" || code == "rotated") && c.proved != null) {
                        events += Ev(step, "refused", url, code = code, created = c.created)
                    }
                }
            }
            if (main.pending == 0 && disk.pending == 0) quiet()
        }

        /** What holds once nothing is left to run. */
        private fun quiet() {
            quietAt = step
            val stored = outside { identities.list() }
            for (i in stored) if (hexOf(i.cert) !in allowed) fail("${i.fingerprint} keeps a certificate nobody confirmed")
            val remembered = outside { servers.all() }
            for (s in all) {
                if ((ended[s.url] ?: -1) > (keptAt[s.url] ?: -1) && outside { servers.session(s) } != null) {
                    fail("${s.url} keeps a session nothing will resume")
                }
                val landed = landedAt[s.url] ?: continue
                val cut = maxOf(forgotAt[s.url] ?: -1, diedAt)
                if (landed > cut && s !in remembered) fail("${s.url} landed, begun at $landed after $cut, and is not remembered")
            }
            conns.lastOrNull { it.epoch == epoch }?.let { screen(it) }
            stores(remembered, stored.map { it.fingerprint })
            val mine = enrs.filter { it.epoch == epoch }
            val open = mine.filter { !it.closed }
            for (e in open.filter { it.quiet }) if (e.asked == null || e.answer.isCompleted) fail("a quiet renewal's device left open")
            val byCode = open.filter { !it.quiet }
            val shown = vm.enrollment.value
            val owns =
                shown is Enrolling.Ready ||
                    shown is Enrolling.Waiting ||
                    shown is Enrolling.Answered ||
                    (shown is Enrolling.Failed && shown.device.isNotEmpty())
            if (byCode.size > (if (owns) 1 else 0)) fail("${byCode.size} enrollments by code open, showing $shown")
            for ((target, n) in mine.filter { !it.quiet }.groupingBy { it.expecting }.eachCount()) {
                if (n > (starts[target] ?: 0)) fail("$n enrollments held to $target for ${starts[target] ?: 0} starts")
            }
            val seeds =
                mine.flatMap { listOfNotNull(it.given) + it.handed } +
                    conns.filter { it.epoch == epoch && it.outcome != null }.flatMap { it.seeds }
            if (seeds.any { s -> s.any { it != 0.toByte() } }) fail("a seed handed out is not wiped")
        }

        /** The screen is [c]'s, the current connection's, and what it saves is [c]'s session. */
        private fun screen(c: Conn) {
            if (c.isClosed) return
            val shown = vm.chat.value
            if (c.outcome?.isFailure == true && shown.link == Link.Connecting) fail("the screen stays connecting after its login failed")
            if (c.loginAsked && !c.landed && c.outcome == null) {
                if (shown.link != Link.Connecting) fail("the screen shows ${shown.link} while its login is out")
                val signedIn = shown.entries.any { it is Entry.SignedIn } || shown.outcome != null
                if (signedIn) fail("signed in on the screen of a login still out")
            }
            if (c.outcome?.isSuccess == true && !c.over && shown.link is Link.Ended) fail("the screen shows ${shown.link} for a live link")
            // Landed to be resumed, nothing since that ends it, and not one the person is leaving.
            if (shown.leaving) return
            val url = c.server.url
            val landed = landedAt[url] ?: return
            val info = c.outcome?.getOrNull() ?: return
            if (!info.canResume || c.over || c.noResume || maxOf(ended[url] ?: -1, forgotAt[url] ?: -1) > landed) return
            val expected = c.session ?: c.resumedWith?.takeIf { info.resumed } ?: return
            if (outside { servers.session(c.server) }?.contentEquals(expected) != true) fail("$url keeps another session than its link's")
        }

        /** What the stores hold, against what was asked of them. */
        private fun stores(
            remembered: List<Server>,
            kept: List<String>,
        ) {
            fun after(
                at: Int,
                kind: String,
                url: String? = null,
                fp: String? = null,
            ) = events.any { it.step > at && it.kind == kind && (url == null || it.url == url) && (fp == null || it.fp == fp) }
            for (s in all) {
                val url = s.url
                // Forgotten, and not landed since: nothing of it is kept.
                val forgot = events.lastOrNull { it.kind == "forget" && it.url == url }
                val landedSince = events.any { it.kind == "landed" && it.url == url && it.created > forgot?.step ?: 0 }
                if (forgot != null && sure(forgot.step) && !landedSince) {
                    val left = outside { listOfNotNull(s.takeIf { s in remembered }, servers.password(s), servers.session(s)) }
                    if (left.isNotEmpty()) fail("$url forgotten, and still kept: $left")
                }
                // A password refused, and no login since: none is kept to be refused again.
                val failed = events.lastOrNull { it.kind == "pwfail" && it.url == url }
                if (failed != null && sure(failed.step) && !after(failed.step, "landed", url) && outside { servers.password(s) } != null) {
                    fail("$url keeps a password it was refused")
                }
                if (s.signIn is SignIn.Identity) refusals(s, ::after)
            }
            // The server last landed on is the one offered first, unless it went.
            val last = events.lastOrNull { it.kind == "landed" }
            if (last != null && sure(last.step) && !after(last.created, "forget", last.url) && !after(last.created, "delete")) {
                val first = outside { servers.last() }?.url
                if (first != last.url) fail("${last.url} landed last, and $first is offered first")
            }
            // Deleted, and not confirmed again: gone.
            for (fp in listOf(FINGERPRINT, FP3)) {
                val deleted = events.lastOrNull { it.kind == "delete" && it.fp == fp } ?: continue
                if (sure(deleted.step) && !after(deleted.step, "confirm", fp = fp) && fp in kept) fail("$fp deleted, and still kept")
            }
        }

        /**
         * A server's refusal of the device, kept from a refusal no forget
         * came after the connection it was refused on, and cleared by one.
         * A delete after it clears it only if its identity was on the phone,
         * and a try again only if the first was: either leaves it unknown.
         */
        private fun refusals(
            s: Server,
            after: (Int, String, String?, String?) -> Boolean,
        ) {
            val mine = events.filter { it.kind == "refused" && it.url == s.url }
            if (mine.any { !sure(it.step) || after(it.created, "delete", null, null) }) return
            val standing = mine.filter { r -> !after(r.created, "forget", s.url, null) }
            if (standing.any { after(it.step, "try", s.url, null) }) return
            if (events.any { it.kind in setOf("forget", "delete", "try") && !sure(it.step) }) return
            val got = outside { servers.refused(s, DEVICE_KEY) }
            if (standing.isEmpty() && got != null) fail("${s.url} keeps a refusal ($got) nothing standing made")
            val codes = standing.map { it.code }
            if (standing.isNotEmpty() && got !in codes) fail("${s.url} keeps $got for refusals $codes")
        }

        private fun fail(what: String): Nothing = throw AssertionError("seed $seed, step $step: $what\n" + log.joinToString("\n"))
    }

    /** Something asked of the stores, at [step]; [created], the step its connection was. */
    private data class Ev(
        val step: Int,
        val kind: String,
        val url: String? = null,
        val fp: String? = null,
        val code: String? = null,
        val created: Int = 0,
    )

    private companion object {
        /** Seeds a run makes, and steps each, unless HEXLINE_SEEDS says otherwise. */
        const val SEEDS = 500
        const val STEPS = 200
        const val TRIES = 8

        /** How long before its holder is asked a quiet renewal's try may be noted, as the model notes it. */
        const val NOTED_WITHIN = 60L

        /** The clock difference a certificate's time is allowed, as the core allows it. */
        const val SKEW = 300L

        /** A third of the fixtures' life left, and a day: due for renewal. */
        const val DUE = ISSUED + (EXPIRES - ISSUED) * 2 / 3 + DAY

        // More devices of the fixture identity's one device, each an hour on
        // from the last, and a second identity's: made with hl-identity.
        val MINTED =
            listOf(
                "a761760163736967584029dde2d6b5c8b4cd41a4ce2595d987b859db20472bfc5aefe78634089dc4272cd73d72a1ba8ac943d8ab883624f53432ede39490296e1af30a95a6ba1ff145076664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b49e01067657870697265731a7e15e310686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a76176016373696758400cb4f4b9b7810757b5f5f2f53bd41ac03678abc2d9153acbe342648002d792898a1ea52d621fd7654348b235493ddd294a2b245902c61eed4f7995d86e45c80b6664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b49ee2067657870697265731a7e15f120686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a76176016373696758400c4d6f6199554016f28f1e9ba36b9446f73b6fcca1df2b74433f92683dbfa6bccd1497f09d1d535036f0418439b224379b77ccce3577f00b33f31c19f60a3b056664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b49fc3067657870697265731a7e15ff30686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a7617601637369675840447bbf7361ef624a6578e106816431c7de0e81e67c242dc3007da4717e78b23da62cb9428f663d69bae940c7ac7cca38d5d9ee24835eced75b82c061bcb5b9016664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b4a0a4067657870697265731a7e160d40686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a761760163736967584064145aa9dd33de39e6ea32c025dab0d5a339a2ea521b5cc0d0ff4a9eff50eb3522222f971694050c788234c785a83a9977989570eb6e8b48a55c871118c2ca0f6664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b4a185067657870697265731a7e161b50686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a7617601637369675840429ad95e7fe8001c5a1a20f20631d3f04915f1832558221cdf47deb9204a59e0ad9ae6c8e63711ee81b6ccf141426765dd62d93eb3e9a02441bd042beaf2bf016664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b4a266067657870697265731a7e162960686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a76176016373696758404d0096b7e1db5d1017cc7a0b62f241aac42dd15a16881f62dc832fc82bcbaf506133499280d44dc6e5dfd12a4c27367126dc4b3fb409bf1d70f938230904770d6664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b4a347067657870697265731a7e163770686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
                "a761760163736967584025ee4c078d1d270421a74eea6eca4a5b15f0b85ffa9e536b4447dbf11f7fbc65ecd870c8efaa16599f2a5a408577ad7e22889b6b159b1bf3ea90f202cdf804006664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b4a428067657870697265731a7e164580686964656e7469747958208a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c6a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
            ).map(::hex)
        val CARD3 =
            hex(
                "a56176016373696758408b8f89c2cde84abc054d51470036762c592a2a8e3a865242abe670c022dd77a3236c222fd57318522e7693552437704560e26f6b46873fc65d12278f2016e60e646e616d65654f7468657267757064617465641a6b49d200686964656e746974795820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
            )
        val CERT3 =
            hex(
                "a7617601637369675840bede4db2e6bd06eec5be91c575a2a3b17e995947afb34ec83e762f6025c0f630073ee2a00347e4f36a46d4a73aeb51597618550aeeebc641ab45e8767db8d8006664657669636558208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394666973737565641a6b49d20067657870697265731a7e15d500686964656e746974795820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d16a6465766963655f656e635820198102e1c39f8bcabb16b9ed3135b4abb72e470139ec8364d882e300ed105c04",
            )
        val FP3: String by lazy { certForDevice(CERT3, CARD3, SEED).fingerprint }

        /** The one device every fixture certifies. */
        val DEVICE_KEY: ByteArray by lazy { certForDevice(CERT, CARD, SEED).device }

        fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

        /** Every certificate the fixtures have, by its identity and when it was issued. */
        val CERTS: Map<Pair<String, ULong>, ByteArray> by lazy {
            (MINTED + listOf(CERT, RENEWED)).map { it to CARD }.plus(CERT3 to CARD3).associate { (cert, card) ->
                certForDevice(cert, card, SEED).let { it.fingerprint to it.issued } to cert
            }
        }

        fun identityOf(cert: ByteArray) =
            CERTS.entries
                .single { it.value.contentEquals(cert) }
                .key.first

        fun enrolled(
            cert: ByteArray,
            card: ByteArray,
        ): Enrolled {
            val info = certForDevice(cert, card, SEED)
            return Enrolled(cert, card, info.fingerprint, info.fingerprint.take(8), if (card === CARD3) "Other" else "Fixture", info)
        }
    }
}
