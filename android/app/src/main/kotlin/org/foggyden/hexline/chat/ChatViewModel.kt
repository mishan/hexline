package org.foggyden.hexline.chat

import android.annotation.SuppressLint
import android.app.Application
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.foggyden.hexline.BuildConfig
import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.core.Connection
import org.foggyden.hexline.core.CoreException
import org.foggyden.hexline.core.CoreUpdate
import org.foggyden.hexline.core.DeviceIdentity
import org.foggyden.hexline.core.Enrollment
import org.foggyden.hexline.core.LoginInfo
import org.foggyden.hexline.core.Restored
import org.foggyden.hexline.core.SecretKind
import org.foggyden.hexline.core.UpdateSink
import org.foggyden.hexline.core.cardName
import org.foggyden.hexline.core.coreConnection
import org.foggyden.hexline.core.coreEnrollment
import org.foggyden.hexline.core.newerCard
import org.foggyden.hexline.core.refusalLasts
import org.foggyden.hexline.core.restoreIdentity
import org.foggyden.hexline.identity.CoreHolderSetups
import org.foggyden.hexline.identity.EnrollProblem
import org.foggyden.hexline.identity.Enrolling
import org.foggyden.hexline.identity.HeldSeeds
import org.foggyden.hexline.identity.HolderRefusal
import org.foggyden.hexline.identity.HolderSetups
import org.foggyden.hexline.identity.Identities
import org.foggyden.hexline.identity.RestoreProblem
import org.foggyden.hexline.identity.Restoring
import org.foggyden.hexline.identity.SettingUp
import org.foggyden.hexline.identity.Setup
import org.foggyden.hexline.identity.SetupProblem
import org.foggyden.hexline.identity.Standing
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.identity.enrollProblem
import org.foggyden.hexline.identity.restoreProblem
import org.foggyden.hexline.identity.setupProblem
import org.foggyden.hexline.identity.standing
import org.foggyden.hexline.identity.usable
import org.foggyden.hexline.secrets.Authorizer
import org.foggyden.hexline.secrets.HeldKeyLost
import org.foggyden.hexline.secrets.HolderUnsupported
import org.foggyden.hexline.secrets.KeystoreHolderKeys
import org.foggyden.hexline.secrets.NoHolderKeys
import org.foggyden.hexline.secrets.NoScreenLock
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SoftwareKeysOnly
import org.foggyden.hexline.servers.SavedServers
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn
import org.foggyden.hexline.servers.StoreQueue
import org.foggyden.hexline.servers.stored
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.ProviderException
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap

/**
 * One server's connection and what its screen shows. The session outlives
 * the screen: in the background the core keeps it detached, and what
 * resumes it is saved, so the app picks it up where it was when it comes
 * back, even in a new process.
 *
 * Everything here but [state] is touched on the main thread alone: the
 * core's batches and the network's callbacks are brought to it.
 */
class ChatViewModel internal constructor(
    app: Application,
    private val servers: SavedServers,
    private val identities: Identities,
    /** The identity seeds this phone holds, whose keys are checked each time the app comes to the front. */
    private val held: HeldSeeds,
    /**
     * Where every read and write of [servers] and [identities] this makes
     * is made. A forget or a delete lets go of what it names on the main
     * thread before it asks for its own work, so queue order is the main
     * thread's. A write the person may leave before it is made is asked
     * for on [StoreQueue.scope], which outlives this.
     */
    private val queue: StoreQueue,
    private val open: (url: String, sink: UpdateSink) -> Connection,
    /**
     * A device to enroll, or with a seed and its certificate that device to
     * renew; with an identity's fingerprint, one kept only from that identity.
     */
    private val enroll: (renewing: Pair<ByteArray, ByteArray>?, expecting: String?) -> Enrollment,
    /** Holders' setups, and restores that hold what they restore. */
    private val setups: HolderSetups,
    /** Seconds since the epoch, that a certificate's time is judged by. */
    private val now: () -> Long,
    /**
     * The process's, whether the app is in front: it outlives every screen,
     * and holds no activity for this to leak.
     */
    @SuppressLint("StaticFieldLeak")
    private val process: Lifecycle,
) : AndroidViewModel(app) {
    /** The one the app makes: its own stores, the process's queue, the core's connections and the clock. */
    constructor(app: Application) : this(
        app,
        SavedServers(app),
        Identities(app),
        HeldSeeds(
            File(app.filesDir, "held"),
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) KeystoreHolderKeys(app) else NoHolderKeys,
            Dispatchers.IO,
            softwareKeys = BuildConfig.DEBUG,
        ),
        StoreQueue.process,
        ::coreConnection,
        ::coreEnrollment,
        CoreHolderSetups,
        { System.currentTimeMillis() / 1000 },
        ProcessLifecycleOwner.get().lifecycle,
    )

    private val store = queue.dispatcher

    /**
     * [work] on the store queue, kept to however the person leaves. A store
     * that cannot be written now (a full disk, the Keystore locked) loses
     * that write and nothing more: it is no reason for the app to fall over.
     */
    private fun later(work: () -> Unit) = queue.scope.launch { stored(work) }

    private val state = MutableStateFlow(ChatState())
    val chat: StateFlow<ChatState> = state

    private val savedServers = MutableStateFlow<List<Server>>(emptyList())

    /** The servers connected to, the last first, to offer again. */
    val saved: StateFlow<List<Server>> = savedServers

    private val kept = MutableStateFlow<List<StoredIdentity>>(emptyList())

    /** The identities this phone is a device of. */
    val identityList: StateFlow<List<StoredIdentity>> = kept

    private val heldLost = MutableStateFlow<List<String>>(emptyList())

    /**
     * Identities this phone held and holds no longer, their key gone with
     * the screen lock: each a device alone here now, until the person has
     * read why.
     */
    val heldLostNotices: StateFlow<List<String>> = heldLost

    private val refused = MutableStateFlow<Map<String, String>>(emptyMap())

    /** What servers refused this phone's devices as, by [org.foggyden.hexline.servers.refusalKey]. */
    val refusals: StateFlow<Map<String, String>> = refused

    private val restoring = MutableStateFlow<Restoring>(Restoring.Idle)
    val restore: StateFlow<Restoring> = restoring

    /** Enrolling this phone, and the device it holds: on the main thread alone. */
    private var enrollState: EnrollState = EnrollState.Idle()
    private val enrolling = MutableStateFlow<Enrolling>(Enrolling.Idle)
    val enrollment: StateFlow<Enrolling> = enrolling

    private val quiet = QuietRenewal(identities, queue, enroll, now) { publishIdentities() }

    // Read from the store queue too, to see a forget that came first.
    @Volatile private var connection: Connection? = null
    private var server: Server? = null

    /**
     * One connection asked for (a connect, the resume at launch), from the
     * moment it is asked, on the main thread before anything waits, to its
     * login landing or failing. A forget or a delete that could name it
     * lets go of it, on the main thread before its own work, and every
     * step after a wait asks [live] first: nothing is started, proved, or
     * kept for a server or an identity let go of. [server] is null while
     * the launch's resume has yet to read which server it is, and any
     * forget or delete lets go of it then.
     */
    private class Attempt(
        var server: Server?,
    ) {
        @Volatile var live = true

        /** Given a connection: what it was answered is its own to keep, whatever is asked for after it. */
        var started = false
    }

    /** Every attempt not yet over; on the main thread. */
    private val attempts = mutableListOf<Attempt>()

    /** The attempt [connection] came of: let go of with it. */
    private var current: Attempt? = null

    private fun attempt(server: Server?) = Attempt(server).also { attempts += it }

    private fun letGo(a: Attempt) {
        a.live = false
        attempts -= a
    }

    /**
     * Lets go of every attempt [names] could be, and the connection if it
     * is one of them: that one through [leave], which logs it out.
     */
    private fun letGo(names: (Server) -> Boolean) {
        for (a in attempts.filter { a -> a !== current && (a.server?.let(names) ?: true) }) letGo(a)
        if (server?.let(names) == true) leave()
    }

    /** The connection has been live: what it saves from now on is its own. */
    private var established = false
    private var foreground = true

    /**
     * Per server and connection, the session write waiting its turn on the
     * store queue, and when it was asked for. Per connection, so a new
     * connection's write is queued behind its own login's remember, never
     * folded into one an earlier connection queued before it.
     */
    private val sessionWrites = ConcurrentHashMap<Pair<Server, Connection>, Pair<ByteArray, Long>>()

    /**
     * One sink per connection, so a late batch from one no longer current
     * changes nothing. Called on a core thread: `update` is atomic, so the
     * batch is applied whole and in order, and the call returns at once, as
     * the core asks.
     */
    private inner class Sink(
        val server: Server,
        /** When its connect was asked for, a [SavedServers.generation]. */
        val since: Long,
    ) : UpdateSink {
        /** The device an identity login proved: the one to mark if a later login is refused. */
        @Volatile var device: ByteArray? = null

        override fun deliver(updates: List<CoreUpdate>) {
            var before: ChatState? = null
            state.update { s ->
                if (sink !== this) return
                before = s
                updates.fold(s) { acc, u -> acc.apply(u) }
            }
            val wasConnecting = before?.link == Link.Connecting
            val kept = updates.any { it is CoreUpdate.SessionKept }
            // A login after a lapse, refused by the server.
            val refused = updates.firstNotNullOfOrNull { (it as? CoreUpdate.Refused)?.code }
            // Kicked, replaced, refused after a lapse, or a new login made by
            // the core that will not survive one: nothing will resume it.
            // Forgotten from here, so a screen that goes before the main
            // thread hears of it cannot keep it.
            val over =
                updates.any {
                    (it is CoreUpdate.Closed && !it.canResume) ||
                        (it is CoreUpdate.Reconnected && it.info?.canResume == false)
                }
            if (over && !state.value.leaving) {
                val at = servers.generation()
                later { servers.forgetSession(server, at) }
            }
            viewModelScope.launch {
                if (refused != null) markRefused(server, device, refused, since)
                if (sink !== this@Sink) return@launch
                if (kept) save()
                // The first page waits for the roster that makes the link live.
                if (wasConnecting && state.value.link == Link.Live) {
                    // Signed in: the connect screen, and any enrolling on it, is left.
                    send(EnrollEvent.Closed)
                    loadEarlier()
                }
                if (state.value.fillAfter != null && state.value.link == Link.Live) fill()
            }
        }
    }

    @Volatile private var sink: Sink? = null

    private val connectivity = app.getSystemService(ConnectivityManager::class.java)

    // On the main thread; the core rate-limits, so every change is passed on.
    private val network =
        object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = nudge()

            override fun onCapabilitiesChanged(
                network: Network,
                capabilities: NetworkCapabilities,
            ) = nudge()

            override fun onLost(network: Network) = nudge()
        }

    private fun nudge() = connection?.networkChanged() ?: Unit

    // The process's, not an activity's: a rotation is not the app going away.
    private val lifecycle =
        object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) = foreground(true)

            override fun onStop(owner: LifecycleOwner) = foreground(false)
        }

    init {
        connectivity.registerDefaultNetworkCallback(network, Handler(Looper.getMainLooper()))
        process.addObserver(lifecycle)
        val ask = attempt(null)
        val since = servers.generation()
        viewModelScope.launch {
            val found =
                withContext(store) {
                    publishIdentities()
                    held.sweep()
                    demoteHeld()
                    publishRefusals()
                    publishServers()
                    servers.last()?.let { Triple(it, servers.session(it), servers.password(it)) }
                }
            // Apart from the resume, which it is not to hold up: a holder may take minutes.
            launch { quiet.run() }
            // A session left without leaving: take it up again, unless let go of while it was read.
            if (found == null || found.second == null || !ask.live) {
                end(ask)
                return@launch
            }
            val (last, session, password) = found
            ask.server = last
            start(last, password, null, session, keep = password, since = since, ask = ask)
        }
    }

    private fun end(ask: Attempt) {
        attempts -= ask
    }

    /**
     * Connects to [wanted], with [link] an existing account's login to link
     * an identity to. A saved server's kept password stands in for none
     * typed, and its session is resumed rather than a second made beside it.
     */
    fun connect(
        wanted: Server,
        password: String?,
        remember: Boolean,
        link: ClassicLogin? = null,
    ) {
        // The last asked for takes the place of any not yet started; one
        // started is its connection's, let go of only by leaving it.
        for (a in attempts.filter { !it.started }) letGo(a)
        val ask = attempt(wanted)
        val since = servers.generation()
        viewModelScope.launch {
            val (kept, saved) =
                if (wanted in savedServers.value) {
                    withContext(store) { servers.password(wanted) to servers.session(wanted).takeIf { link == null } }
                } else {
                    null to null
                }
            // Let go of while its secrets were read.
            if (!ask.live) return@launch end(ask)
            start(wanted, password ?: kept, link, saved, passwordToKeep(password, kept, remember), since, ask)
        }
    }

    /**
     * Forgets [server], and lets go of its connection if it has one, so
     * nothing it does after (a login landing, a session saved on the way
     * out) remembers it again.
     */
    fun forget(server: Server) {
        // Forgetting a server is leaving it: no session is left behind that
        // nothing will resume or end.
        letGo { it == server }
        val at = servers.generation()
        later {
            servers.forget(server, at)
            publishRefusals()
            publishServers()
        }
    }

    /**
     * Makes this phone a device of the identity a registrar keeps for
     * [handle]; with [holdWith], holding its key too, behind that prompt.
     */
    fun restore(
        registrar: String,
        handle: String,
        kind: SecretKind,
        secret: String,
        deviceName: String,
        holdWith: Authorizer? = null,
    ) {
        if (restoring.value == Restoring.Working) return
        restoring.value = Restoring.Working
        viewModelScope.launch {
            var made: Restored? = null
            // Once the store's task has the seed, it is that task's to wipe.
            var handed = false
            var identitySeed: ByteArray? = null
            restoring.value =
                try {
                    val device =
                        if (holdWith == null) {
                            restoreIdentity(registrar, handle, kind, secret, deviceName)
                        } else {
                            withContext(store) { held.probe() }
                            setups.restoreToHold(registrar, handle, kind, secret, deviceName).let {
                                identitySeed = it.identitySeed
                                it.device
                            }
                        }.also { made = it }
                    val at = servers.generation()
                    handed = true
                    queue.scope
                        .async {
                            try {
                                val replaced =
                                    identities
                                        .list()
                                        .find { it.fingerprint == device.fingerprint }
                                        ?.info
                                        ?.device
                                identities.save(device.seed, device.cert, device.card, handle, registrar)
                                // The new device starts with no server's refusal; the old one's go with it.
                                replaced?.let {
                                    servers.forgetRefusalsOf(it, at)
                                    publishRefusals()
                                }
                                publishIdentities()
                            } finally {
                                device.seed.fill(0)
                            }
                        }.await()
                    val seed = identitySeed
                    // Kept as a device first: a prompt refused leaves it one, and says so.
                    if (seed != null && holdWith != null && !held.hold(device.fingerprint, seed, holdWith)) {
                        Restoring.NotHeld(device.fingerprint)
                    } else {
                        Restoring.Done(device.fingerprint)
                    }
                } catch (e: CoreException) {
                    Restoring.Failed(restoreProblem(e))
                } catch (_: SecretUnavailable) {
                    Restoring.Failed(RestoreProblem.NotKept)
                } catch (_: IOException) {
                    Restoring.Failed(RestoreProblem.NotKept)
                } catch (_: NoScreenLock) {
                    Restoring.Failed(RestoreProblem.NoScreenLock)
                } catch (_: SoftwareKeysOnly) {
                    Restoring.Failed(RestoreProblem.SoftwareOnly)
                } catch (_: HolderUnsupported) {
                    Restoring.Failed(RestoreProblem.TooOld)
                } catch (_: GeneralSecurityException) {
                    Restoring.Failed(RestoreProblem.NotKept)
                } catch (_: ProviderException) {
                    Restoring.Failed(RestoreProblem.NotKept)
                } finally {
                    if (!handed) made?.seed?.fill(0)
                    identitySeed?.fill(0)
                }
        }
    }

    /** Opens enrolling for a new identity, or to renew [renewing] (a fingerprint). */
    fun startEnroll(renewing: String?) = send(EnrollEvent.Start(renewing))

    /** Asks the holder at [mailbox] to certify run [gen]'s device, by [code]. */
    fun requestEnroll(
        gen: Int,
        mailbox: String,
        code: String,
        name: String,
    ) = send(EnrollEvent.Request(gen, mailbox, code, name))

    /** Keeps run [gen]'s answer, if it is still the one for [shown], the identity the screen showed. */
    fun confirmEnroll(
        gen: Int,
        shown: String,
    ) = send(EnrollEvent.Confirm(gen, shown))

    /** Stops enrolling: a wait for the holder ends, and the device and any answer are dropped. */
    fun discardEnroll() = send(EnrollEvent.Discard)

    fun enrollSeen() = send(EnrollEvent.Seen)

    /** One step of enrolling, and what it asks for done; on the main thread. */
    private fun send(event: EnrollEvent) {
        val (next, effects) = reduce(enrollState, event)
        enrollState = next
        enrolling.value = next.shown()
        effects.forEach(::run)
    }

    private fun run(effect: EnrollEffect) {
        when (effect) {
            is EnrollEffect.Close -> {
                effect.enrollee.cancel()
                effect.enrollee.close()
            }
            is EnrollEffect.Make -> make(effect.gen, effect.renewing)
            is EnrollEffect.Enroll -> ask(effect)
            is EnrollEffect.Save -> save(effect)
        }
    }

    /**
     * The device for run [gen]: new, or for [renewing] the one kept for it,
     * which still in its time asks again as itself; lapsed, unreadable or
     * gone, a new device is made, and still held to that identity
     * (enrollment section 8).
     */
    private fun make(
        gen: Int,
        renewing: String?,
    ) = viewModelScope.launch {
        var seed: ByteArray? = null
        val made =
            try {
                val kept = renewing?.let { fp -> withContext(store) { identities.device(fp)?.also { seed = it.second } } }
                val again = kept?.takeIf { standing(it.first, now()).usable }
                enroll(again?.let { it.second to it.first.cert }, renewing)
            } catch (_: SecretUnavailable) {
                null
            } catch (_: CoreException) {
                null
            } finally {
                seed?.fill(0)
            }
        send(EnrollEvent.Made(gen, made, made?.deviceFingerprint().orEmpty()))
    }

    private fun ask(effect: EnrollEffect.Enroll) =
        viewModelScope.launch {
            val answered =
                try {
                    val answer = effect.enrollee.enroll(effect.mailbox, effect.code, effect.name)
                    val replaces = kept.value.find { it.fingerprint == answer.fingerprint }?.info
                    // Another identity on the phone already goes by this name: one may be passing for the other.
                    val named = answer.name.lowercase(Locale.ROOT)
                    val namesake =
                        replaces == null &&
                            kept.value.any { it.fingerprint != answer.fingerprint && cardName(it.card)?.lowercase(Locale.ROOT) == named }
                    EnrollEvent.Answer(effect.gen, answer, replaces, namesake)
                } catch (e: CoreException) {
                    val reason = (e as? CoreException.Refused)?.takeIf { it.code == "denied" }?.detail?.ifEmpty { null }
                    EnrollEvent.Refused(effect.gen, enrollProblem(e), reason)
                }
            send(answered)
        }

    /**
     * Keeps the device the holder certified, now that the person has seen
     * whose it has become; the device it replaces for the same identity,
     * and that one's refusals, go.
     */
    private fun save(effect: EnrollEffect.Save) {
        val (answer, mailbox) = effect.answer to effect.mailbox
        val at = servers.generation()
        val seed = effect.enrollee.seed()
        effect.enrollee.close()
        viewModelScope.launch {
            val saved =
                try {
                    queue.scope
                        .async {
                            try {
                                val before = identities.list().find { it.fingerprint == answer.fingerprint }
                                // The handle is a registrar's word, not the card's name, and a newer card stays.
                                val card = before?.let { newerCard(it.card, answer.card) } ?: answer.card
                                val kept = identities.save(seed, answer.cert, card, before?.handle, null, mailbox)
                                // A new device starts with no server's refusal; the old one's go with it.
                                before?.info?.device?.takeIf { !it.contentEquals(kept.info.device) }?.let {
                                    servers.forgetRefusalsOf(it, at)
                                    publishRefusals()
                                }
                                publishIdentities()
                            } finally {
                                seed.fill(0)
                            }
                        }.await()
                    EnrollEvent.Saved(effect.gen, answer.fingerprint, null)
                } catch (_: SecretUnavailable) {
                    EnrollEvent.Saved(effect.gen, null, EnrollProblem.AnswerNotKept)
                } catch (_: IOException) {
                    EnrollEvent.Saved(effect.gen, null, EnrollProblem.AnswerNotKept)
                } catch (_: CoreException) {
                    EnrollEvent.Saved(effect.gen, null, EnrollProblem.NotForThisPhone)
                }
            send(saved)
        }
    }

    fun restoreSeen() {
        if (restoring.value != Restoring.Working) restoring.value = Restoring.Idle
    }

    private val settingUp = MutableStateFlow<SettingUp>(SettingUp.Idle)

    /** A holder's identity being set up on this phone. */
    val holderSetup: StateFlow<SettingUp> = settingUp

    /** The setup under way: on the main thread alone, as what it is for. */
    private var setup: Setup? = null
    private var setupFor: SetupFor? = null

    private data class SetupFor(
        val registrar: String,
        val handle: String,
        val invite: String?,
        val deviceName: String,
        /** Its device is kept, unfinished, and its seed held: what is left is the commit. */
        val kept: Boolean,
        /** Finished again after the process that began it ended. */
        val resumed: Boolean,
        /** The card a commit the core made gave back, if keeping it here has yet to be done. */
        val committed: ByteArray? = null,
    )

    /**
     * Starts setting up an identity this phone holds, as [handle] at
     * [registrar]: once the phone and the registrar are found able to,
     * the successor's code is shown.
     */
    fun startHolderSetup(
        registrar: String,
        handle: String,
        invite: String?,
        deviceName: String,
    ) {
        if (settingUp.value == SettingUp.Checking || settingUp.value == SettingUp.Working) return
        closeSetup()
        settingUp.value = SettingUp.Checking
        viewModelScope.launch {
            settingUp.value =
                holderStep(handle, fixed = false) {
                    setups.checkDeviceName(deviceName)
                    withContext(store) { held.probe() }
                    setups.check(registrar)
                    val made = setups.new(handle)
                    setup = made
                    setupFor = SetupFor(registrar, handle, invite?.ifBlank { null }, deviceName, kept = false, resumed = false)
                    SettingUp.Successor(shown(made.successorCode()))
                } ?: SettingUp.Idle
        }
    }

    fun successorWritten() {
        if (settingUp.value is SettingUp.Successor) settingUp.value = SettingUp.ConfirmSuccessor(false)
    }

    fun showSuccessorAgain() {
        if (settingUp.value !is SettingUp.ConfirmSuccessor) return
        val code = setup?.successorCode() ?: return
        settingUp.value = SettingUp.Successor(shown(code))
    }

    /** The successor's code as typed back; [typed] is wiped. */
    fun confirmSuccessor(typed: ByteArray) {
        val made = setup
        val right =
            try {
                settingUp.value is SettingUp.ConfirmSuccessor && made != null && made.confirmSuccessor(typed)
            } finally {
                typed.fill(0)
            }
        if (settingUp.value !is SettingUp.ConfirmSuccessor) return
        settingUp.value =
            if (right) SettingUp.Recovery(shown(checkNotNull(made).recoveryCode()), replaces = false) else SettingUp.ConfirmSuccessor(true)
    }

    fun recoveryWritten() {
        (settingUp.value as? SettingUp.Recovery)?.let { settingUp.value = SettingUp.ConfirmRecovery(false, it.replaces) }
    }

    fun showRecoveryAgain() {
        val shown = settingUp.value as? SettingUp.ConfirmRecovery ?: return
        val code = setup?.recoveryCode() ?: return
        settingUp.value = SettingUp.Recovery(shown(code), shown.replaces)
    }

    /** The recovery code as typed back; [typed] is wiped. */
    fun confirmRecovery(typed: ByteArray) {
        val asked = settingUp.value as? SettingUp.ConfirmRecovery
        val made = setup
        val right =
            try {
                asked != null && made != null && made.confirmRecovery(typed)
            } finally {
                typed.fill(0)
            }
        if (asked == null) return
        when {
            !right -> settingUp.value = asked.copy(wrong = true)
            setupFor?.kept == true -> commitSetup()
            else -> settingUp.value = SettingUp.ReadyToHold
        }
    }

    /**
     * Holds the setup's seed behind [authorizer]'s prompt, keeps this
     * phone's device for it, unfinished, and commits it. A prompt refused
     * leaves it ready to hold.
     */
    fun holdSetup(authorizer: Authorizer) {
        val made = setup ?: return
        val target = setupFor ?: return
        if (settingUp.value != SettingUp.ReadyToHold) return
        settingUp.value = SettingUp.Working
        viewModelScope.launch {
            val step =
                holderStep(target.handle, fixed = false) {
                    val fingerprint = made.fingerprint()
                    // Minted first: what would refuse it is found before the person is asked.
                    val minted = made.mint(target.deviceName)
                    try {
                        val seed = made.identitySeed()
                        val holds =
                            try {
                                held.hold(fingerprint, seed, authorizer)
                            } finally {
                                seed.fill(0)
                            }
                        if (!holds) return@holderStep SettingUp.ReadyToHold
                        withContext(store) {
                            identities.save(minted.deviceSeed, minted.cert, made.card(), target.handle, target.registrar, unfinished = true)
                            publishIdentities()
                        }
                    } finally {
                        minted.deviceSeed.fill(0)
                    }
                    made.held()
                    setupFor = target.copy(kept = true)
                    null
                }
            if (step != null) settingUp.value = step else commitSetup()
        }
    }

    /**
     * After a failed step: the setup asked again, as [handle] with [invite]
     * where the handle may still change, as it was where it may not.
     */
    fun retrySetup(
        handle: String,
        invite: String?,
    ) {
        val failed = settingUp.value as? SettingUp.Failed ?: return
        val target = setupFor
        // Failed before any code was made: back to the form, as it was filled in.
        if (setup == null || target == null) {
            settingUp.value = SettingUp.Idle
            return
        }
        if (!target.kept) {
            settingUp.value = SettingUp.ReadyToHold
            return
        }
        // A commit the registrar made is of its handle: only keeping it here is asked again.
        val next = if (failed.fixed || target.committed != null) target.handle else handle.trim()
        setupFor = target.copy(handle = next, invite = invite?.ifBlank { null } ?: target.invite)
        if (next != target.handle) {
            val fingerprint = checkNotNull(setup).fingerprint()
            later { identities.intends(fingerprint, next) }
        }
        commitSetup()
    }

    /**
     * Finishes [fingerprint]'s setup, kept unfinished by a process that
     * ended: its seed opened behind [authorizer]'s prompt, and committed
     * again under a new recovery code, shown first, which replaces any
     * written down before.
     */
    fun finishSetup(
        fingerprint: String,
        authorizer: Authorizer,
    ) {
        if (settingUp.value == SettingUp.Checking || settingUp.value == SettingUp.Working) return
        closeSetup()
        settingUp.value = SettingUp.Working
        viewModelScope.launch {
            var handle = ""
            settingUp.value =
                holderStep({ handle }, fixed = true) {
                    val (kept, deviceSeed) = withContext(store) { identities.device(fingerprint) } ?: return@holderStep SettingUp.Idle
                    if (!kept.unfinished) {
                        deviceSeed.fill(0)
                        return@holderStep SettingUp.Idle
                    }
                    handle = kept.handle.orEmpty()
                    val registrar = kept.registrar.orEmpty()
                    val made =
                        try {
                            held.use(fingerprint, authorizer) { seed ->
                                setups.resume(seed, kept.card, registrar, handle, deviceSeed, kept.cert)
                            }
                        } finally {
                            deviceSeed.fill(0)
                        }
                    when {
                        made != null -> {
                            setup = made
                            setupFor = SetupFor(registrar, handle, null, "", kept = true, resumed = true)
                            SettingUp.Recovery(shown(made.recoveryCode()), replaces = true)
                        }
                        // Not held now: its key went while the app was away.
                        !held.isHeld(fingerprint) -> {
                            withContext(store) {
                                demoteHeld()
                                identities.unrecoverable(fingerprint)
                                publishIdentities()
                            }
                            SettingUp.Failed(SetupProblem.KeyLost, handle, fixed = true)
                        }
                        else -> SettingUp.Idle
                    }
                } ?: SettingUp.Idle
        }
    }

    /** Lets go of the setup under way: what it kept goes, and a device kept for it stays, unfinished. */
    fun cancelHolderSetup() {
        if (settingUp.value == SettingUp.Working) return
        // A seed held for a device that was never kept would be held unseen.
        if (setupFor?.kept == false) setup?.fingerprint()?.let { fingerprint -> later { held.forget(fingerprint) } }
        closeSetup()
        settingUp.value = SettingUp.Idle
    }

    fun holderSetupSeen() {
        when (settingUp.value) {
            is SettingUp.Done, is SettingUp.Refused -> settingUp.value = SettingUp.Idle
            else -> Unit
        }
    }

    private fun commitSetup() {
        val made = setup ?: return
        val target = setupFor ?: return
        settingUp.value = SettingUp.Working
        viewModelScope.launch {
            val fingerprint = made.fingerprint()
            settingUp.value =
                holderStep(target.handle, fixed = target.resumed) {
                    // Committed at the registrar already, only keeping it here is asked again.
                    val card = target.committed ?: made.commit(target.registrar, target.handle, target.invite).card
                    setupFor = target.copy(committed = card)
                    withContext(store) {
                        // As the registrar took it, whatever the write of what was intended made of it.
                        identities.committed(fingerprint, card, target.handle)
                        publishIdentities()
                    }
                    closeSetup()
                    SettingUp.Done(fingerprint)
                } ?: SettingUp.Idle
        }
    }

    /**
     * [step]'s state, or what a step refused for says: a refusal of the
     * phone, or a problem asking [handle] again, which may no longer
     * change once [fixed] or once it is the identity's.
     */
    private suspend fun holderStep(
        handle: () -> String,
        fixed: Boolean,
        step: suspend () -> SettingUp?,
    ): SettingUp? =
        try {
            step()
        } catch (_: NoScreenLock) {
            SettingUp.Refused(HolderRefusal.NoScreenLock)
        } catch (_: SoftwareKeysOnly) {
            SettingUp.Refused(HolderRefusal.SoftwareOnly)
        } catch (_: HolderUnsupported) {
            SettingUp.Refused(HolderRefusal.TooOld)
        } catch (_: HeldKeyLost) {
            withContext(store) { demoteHeld() }
            SettingUp.Failed(SetupProblem.KeyLost, handle(), fixed = true)
        } catch (e: CoreException) {
            val problem = setupProblem(e)
            // A resumed setup refused its handle may take another; the core says so.
            val stuck =
                problem == SetupProblem.NotBackedUp ||
                    (fixed && problem != SetupProblem.HandleTaken && problem != SetupProblem.HandleInvalid)
            SettingUp.Failed(problem, handle(), stuck)
        } catch (_: SecretUnavailable) {
            SettingUp.Failed(SetupProblem.NotKept, handle(), fixed)
        } catch (_: IOException) {
            SettingUp.Failed(SetupProblem.NotKept, handle(), fixed)
        } catch (_: GeneralSecurityException) {
            SettingUp.Failed(SetupProblem.NotKept, handle(), fixed)
        } catch (_: ProviderException) {
            SettingUp.Failed(SetupProblem.NotKept, handle(), fixed)
        }

    private suspend fun holderStep(
        handle: String,
        fixed: Boolean,
        step: suspend () -> SettingUp?,
    ) = holderStep({ handle }, fixed, step)

    private fun closeSetup() {
        setup?.close()
        setup = null
        setupFor = null
    }

    /** A code as shown: the bytes it came in wiped. */
    private fun shown(code: ByteArray?): String {
        val bytes = checkNotNull(code) { "no code to show" }
        return try {
            String(bytes, Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    /** Logs out of the current connection and lets go of it. */
    private fun leave() {
        current?.let(::letGo)
        current = null
        sink = null
        connection?.let {
            it.hangUp(true)
            it.close()
        }
        connection = null
        this.server = null
        state.value = ChatState()
    }

    /**
     * Forgets [fingerprint]'s identity, its device's seed, and what every
     * saved server kept for it (a session, a refusal), and logs out of the
     * current connection if it is signed in as it.
     */
    fun deleteIdentity(fingerprint: String) {
        val signedIn = SignIn.Identity(fingerprint)
        // A connect asked for after this reads the device after it, and finds none.
        letGo { it.signIn == signedIn }
        // Asked for now: what a login asked for after this keeps is not this delete's to clear.
        val since = servers.generation()
        later {
            val device =
                identities
                    .list()
                    .find { it.fingerprint == fingerprint }
                    ?.info
                    ?.device
            // The held seed first: an identity gone with its seed left would hold it unseen.
            held.forget(fingerprint)
            held.dismiss(fingerprint)
            identities.delete(fingerprint)
            heldLost.value = held.notices()
            publishIdentities()
            for (s in servers.all().filter { it.signIn == signedIn }) servers.forgetSession(s, since)
            device?.let { servers.forgetRefusalsOf(it, since) }
            publishRefusals()
        }
    }

    /**
     * Forgets [server]'s refusal of [fingerprint]'s device, so a login
     * tries it there again: the server may have lifted it.
     */
    fun tryAgain(
        server: Server,
        fingerprint: String,
    ) {
        later {
            identities.list().find { it.fingerprint == fingerprint }?.let { servers.forgetRefusal(server, it.info.device) }
            publishRefusals()
        }
    }

    /** The person has read why [fingerprint] is held no longer. */
    fun dismissHeldLost(fingerprint: String) {
        later {
            held.dismiss(fingerprint)
            heldLost.value = held.notices()
        }
    }

    /** Lets go of each held identity whose key went with the screen lock; on the store queue. */
    private fun demoteHeld() {
        val kept = identities.list()
        val lost = held.demoteLost(kept.map { it.fingerprint })
        // Its key gone before it was committed, a setup has nothing left to finish or recover.
        for (identity in kept) if (identity.unfinished && identity.fingerprint in lost) identities.unrecoverable(identity.fingerprint)
        if (lost.isNotEmpty()) publishIdentities()
        heldLost.value = held.notices()
    }

    // Called on the store queue alone, so a slower read is never shown over a newer one.
    private fun publishIdentities() {
        kept.value = identities.list()
    }

    private fun publishServers() {
        savedServers.value = servers.all()
    }

    private fun publishRefusals() {
        refused.value = servers.refusals()
    }

    /**
     * Keeps [server]'s refusal of [device] when only a new device answers
     * it: that device is not offered to sign in there again, and is
     * everywhere else.
     */
    private fun markRefused(
        server: Server,
        device: ByteArray?,
        code: String,
        since: Long,
    ) {
        if (server.signIn !is SignIn.Identity || device == null || !refusalLasts(code)) return
        later {
            servers.markRefused(server, device, code, since)
            publishRefusals()
        }
    }

    private class NoIdentity : Exception()

    /** An identity this phone will not sign in to [to] with, and why. */
    private class Unusable(
        val why: Why,
    ) : Exception()

    /**
     * Logs in to [to] as the identity [fingerprint] names, its seed wiped
     * once handed over; not with a certificate outside its time, nor a
     * device [to] refused, and not resumed with either.
     */
    private suspend fun loginIdentity(
        conn: Connection,
        ask: Attempt,
        to: Server,
        fingerprint: String,
        create: Boolean,
        link: ClassicLogin?,
        saved: ByteArray?,
        proving: (ByteArray) -> Unit,
    ): LoginInfo {
        // Held outside the read, so a cancellation after it still wipes it.
        var seed: ByteArray? = null
        try {
            val (stored, mine) =
                withContext(store) { identities.device(fingerprint)?.also { seed = it.second } }
                    ?: throw NoIdentity()
            when (standing(stored, now())) {
                Standing.Expired -> throw Unusable(Why.CertExpired)
                Standing.NotYetValid -> throw Unusable(Why.CertNotYetValid)
                else -> {}
            }
            withContext(store) { servers.refused(to, stored.info.device) }?.let { throw Unusable(refusal(it)) }
            // Let go of while the reads were made: nothing is proved for it,
            // and its connection, closed, would take no call.
            if (!ask.live) throw CancellationException("let go of")
            proving(stored.info.device)
            return conn.loginIdentity(DeviceIdentity(mine, stored.cert, stored.card), create, link, saved)
        } finally {
            seed?.fill(0)
        }
    }

    private fun start(
        to: Server,
        password: String?,
        link: ClassicLogin?,
        saved: ByteArray?,
        keep: String?,
        since: Long,
        ask: Attempt,
    ) {
        if (state.value.link.let { it == Link.Connecting || it == Link.Live || it is Link.Reconnecting }) return end(ask)
        state.value = ChatState(link = Link.Connecting)
        // The one replaced has had its login's answer, and its link has ended
        // since (else this would not be starting): what it asked to keep of
        // that answer (a server remembered, a refused session cleared) is still
        // made, while the screen, and what it saves, are this one's from here.
        current = ask
        ask.started = true
        connection?.let {
            connection = null
            it.close()
        }
        val mine = Sink(to, since)
        sink = mine
        val conn = open(to.url, mine)
        conn.setForeground(foreground)
        connection = conn
        server = to
        established = false
        viewModelScope.launch {
            try {
                val info =
                    when (val how = to.signIn) {
                        SignIn.Password -> conn.login(loginFor(to, password, saved), password, saved)
                        is SignIn.Identity -> {
                            // An account named to link and not linked yet is
                            // never made in its place.
                            val asked = link != null || withContext(store) { servers.linkAsked(to) }
                            loginIdentity(conn, ask, to, how.fingerprint, !asked, link, saved) { mine.device = it }
                        }
                    }
                // Let go of while logging in: nothing of it is kept.
                if (!ask.live) return@launch
                later {
                    if (!ask.live) return@later
                    if (!servers.remember(to, keep.takeIf { to.signIn == SignIn.Password }, since)) return@later
                    if (to.signIn is SignIn.Identity && !info.resumed) {
                        servers.askedToLink(to, info.outcome != "linked" && (link != null || servers.linkAsked(to)), since)
                    }
                    publishServers()
                }
                // A session the server will not let survive a lapse is no session to keep.
                if (!info.canResume) later { servers.forgetSession(to, since) }
                // Its link ended, and another begun, before this ran: the core
                // runs a link from the moment it answers.
                if (sink !== mine) return@launch
                established = true
                state.update { if (info.resumed) it.copy(outcome = info.outcome) else it.signedIn(info.outcome) }
                // Queued after the remember, which a session is kept only beside.
                save()
            } catch (_: NoIdentity) {
                if (!ask.live || sink !== mine) return@launch
                state.update { it.copy(link = Link.Ended(Why.NoIdentity)) }
            } catch (e: Unusable) {
                if (!ask.live || sink !== mine) return@launch
                state.update { it.copy(link = Link.Ended(e.why)) }
            } catch (_: SecretUnavailable) {
                if (!ask.live || sink !== mine) return@launch
                state.update { it.copy(link = Link.Ended(Why.KeyLocked)) }
            } catch (e: CoreException) {
                val code = (e as? CoreException.Refused)?.code
                // Kept whether or not this is still the connection: the
                // server said it of this device, and a forget since is
                // honored by the generation.
                if (code != null) markRefused(to, mine.device, code, since)
                if (!ask.live) return@launch
                later {
                    // Refused for good: the saved session is not coming back.
                    // Busy or unreachable, it may yet.
                    // Its own to clear: not if let go of since, nor what a newer login kept.
                    if (!ask.live) return@later
                    if (saved != null && code != null && !keepsSession(code)) servers.forgetSession(to, since)
                    if (code == "login_failed") servers.forgetPassword(to, since)
                }
                if (!ask.live || sink !== mine) return@launch
                state.update { it.copy(link = Link.Ended(why(e))) }
            } finally {
                end(ask)
            }
        }
    }

    fun send(text: String) {
        val conn = connection ?: return
        if (text.isBlank()) return
        viewModelScope.launch {
            try {
                conn.chat(text)
            } catch (e: CoreException) {
                state.update { it.notSent(why(e)) }
            }
        }
    }

    private var loading = false

    fun loadEarlier() {
        val conn = connection ?: return
        if (loading || !state.value.earlierToLoad || state.value.link != Link.Live) return
        loading = true
        viewModelScope.launch {
            try {
                val page = conn.history(state.value.oldestId, null, PAGE)
                state.update { it.withEarlier(page.lines, page.hasMore) }
            } catch (e: CoreException) {
                // A server that keeps no history has none to load; anything
                // else is worth trying again when the reader scrolls back.
                if (e is CoreException.Refused && e.code == "not_available") {
                    state.update { it.copy(earlierToLoad = false) }
                }
            } finally {
                loading = false
            }
        }
    }

    private var filling = false

    /** The lines said while the link was down, a page at a time, up to a bound. */
    private suspend fun fill() {
        val conn = connection ?: return
        if (filling) return
        filling = true
        try {
            var pages = 0
            while (true) {
                val after = state.value.fillAfter ?: return
                if (pages == FILL_PAGES) {
                    state.update { it.withMissed() }
                    return
                }
                // Let go of while it waited: a closed connection takes no call.
                if (connection !== conn) return
                try {
                    val page = conn.history(null, after, FILL_PAGE)
                    state.update { it.withLater(page.lines, page.hasMore) }
                    pages++
                } catch (e: CoreException) {
                    when {
                        e is CoreException.Refused && e.code == "not_available" -> {
                            state.update { it.withMissed() }
                            return
                        }
                        // Paged too fast: wait, and go on.
                        e is CoreException.Refused && e.code == "rate_limited" -> delay(FILL_WAIT)
                        // The link went; the next batch from a live one tries again.
                        else -> return
                    }
                }
            }
        } finally {
            filling = false
        }
    }

    private fun foreground(foreground: Boolean) {
        this.foreground = foreground
        connection?.setForeground(foreground)
        if (!foreground) save()
        if (foreground) {
            later { demoteHeld() }
            viewModelScope.launch { quiet.run() }
        }
    }

    /**
     * Writes what resumes the session, once the connection has been live and
     * unless the person is leaving: before that, none is what it has, and a
     * session kept from before must not be overwritten with nothing.
     */
    private fun save() {
        val (conn, to) = (connection ?: return) to (server ?: return)
        if (!established || state.value.leaving) return
        // None until the core's first batch: not a reason to forget the one kept.
        val saved = conn.saved() ?: return
        // Asked for now: a clear that comes first wins, even if this write lands after it.
        val since = servers.generation()
        // The core tells a busy link's session after every batch: one write
        // waits at a time, taking the newest asked for when its turn comes.
        val key = to to conn
        if (sessionWrites.put(key, saved to since) == null) {
            later { sessionWrites.remove(key)?.let { (bytes, at) -> servers.keepSession(to, bytes, at) } }
        }
    }

    fun disconnect() {
        val (conn, to) = (connection ?: return) to (server ?: return)
        state.update { it.copy(leaving = true) }
        val at = servers.generation()
        viewModelScope.launch {
            // Forgotten first, so a process gone before the logout lands does
            // not wake up in the chat the person left.
            later { servers.forgetSession(to, at) }.join()
            // Let go of meanwhile (a forget, a delete), which logged it out already.
            if (connection === conn) conn.disconnect()
        }
    }

    // The scope is already cancelled here: save what resumes the session
    // on the store queue, which outlives this, hang up leaving it to be
    // resumed, and let the core finish on its own threads.
    override fun onCleared() {
        closeSetup()
        connectivity.unregisterNetworkCallback(network)
        process.removeObserver(lifecycle)
        send(EnrollEvent.Closed)
        sink = null
        val (conn, to) = (connection ?: return) to (server ?: return)
        connection = null
        val leaving = state.value.leaving
        val saved = conn.saved().takeIf { established && !leaving }
        conn.hangUp(leaving)
        conn.close()
        val since = servers.generation()
        // Leaving, the kept one goes; staying, the core's, once it has one.
        if (leaving || saved != null) later { servers.keepSession(to, saved, since) }
    }

    private fun why(e: CoreException): Why =
        when (e) {
            is CoreException.Connect -> Why.Unreachable
            is CoreException.Refused -> refusal(e.code)
            is CoreException.Protocol -> Why.NotUnderstood
            is CoreException.RateLimited -> Why.Refused("rate_limited")
            is CoreException.Closed, is CoreException.Busy -> Why.Lost
        }

    private companion object {
        const val PAGE = 50u
        const val FILL_PAGE = 200u
        const val FILL_PAGES = 5
        const val FILL_WAIT = 2_000L
    }
}
