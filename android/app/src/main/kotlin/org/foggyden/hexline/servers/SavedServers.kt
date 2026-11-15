package org.foggyden.hexline.servers

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import org.foggyden.hexline.core.partsHash
import org.foggyden.hexline.core.shortHash
import org.foggyden.hexline.secrets.SecretStore
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SecretUnreadable
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException

/** How a server is signed in to. */
sealed interface SignIn {
    data object Password : SignIn

    /** As the identity [fingerprint] names, by the device this phone keeps of it. */
    data class Identity(
        val fingerprint: String,
    ) : SignIn
}

/**
 * A server as the app connects to it: where, and as whom. A password's
 * login is null for a guest; an identity's is always null, as the server
 * finds the account by the identity.
 */
data class Server(
    val url: String,
    val login: String?,
    val signIn: SignIn = SignIn.Password,
)

/**
 * The servers the app has connected to, the last first, each with how it
 * signs in, so a server is never asked about twice. Addresses and logins
 * are kept in preferences; a password, when the person asked for it to be
 * kept, and the session to resume are secrets, in the [SecretStore].
 *
 * Calls block on the Keystore: not on the main thread. A secret that will
 * never open is forgotten and read as none; one that cannot be opened now is
 * read as none and left for later.
 */
class SavedServers(
    context: Context,
    private val secrets: SecretStore = SecretStore(context),
    private val prefs: SharedPreferences = context.getSharedPreferences("servers", Context.MODE_PRIVATE),
) {
    fun all(): List<Server> {
        forgetTheOneKeptBefore()
        val list = JSONArray(prefs.getString(SERVERS, null) ?: return emptyList())
        return (0 until list.length()).map { i ->
            val o = list.getJSONObject(i)
            val login = if (o.has(LOGIN)) o.getString(LOGIN) else null
            val signIn = if (o.has(IDENTITY)) SignIn.Identity(o.getString(IDENTITY)) else SignIn.Password
            Server(o.getString(URL), login, signIn)
        }
    }

    fun last(): Server? = all().firstOrNull()

    /**
     * A ticket for an act asked for now, later than every one before it:
     * taken as the act is asked for and handed to it, so acts are ordered
     * here by when they were asked for, not by when they ran.
     */
    fun generation(): Long = synchronized(LOCK) { ++forgets }

    /**
     * [server] is the last; its password is kept, or with null forgotten.
     * With [since], a [generation], not if [server] has been forgotten
     * since then: a login that lands after its server was forgotten does
     * not bring it back. Whether it was remembered.
     */
    fun remember(
        server: Server,
        password: String?,
        since: Long? = null,
    ): Boolean =
        synchronized(LOCK) {
            if (since != null && (forgottenAt[name("list", server)] ?: 0) > since) return false
            write(listOf(server) + all().filter { it != server })
            write(name("password", server), password?.toByteArray())
            if (password != null) kept(name("password", server), since)
            true
        }

    /** [server] is forgotten whole, its secrets with it; [at], a [generation], when that was asked for. */
    fun forget(
        server: Server,
        at: Long? = null,
    ): Unit =
        synchronized(LOCK) {
            forgotten(name("list", server), at)
            write(all().filter { it != server })
            secrets.delete(name("password", server))
            secrets.delete(name("session", server))
            askedToLink(server, false)
            forgetRefusals(server)
        }

    /**
     * What [server] refused [device] as, `revoked` or `rotated`, or null.
     * Kept for that server and that device alone: a server's word, not
     * signed by anyone, is no reason to stop signing in elsewhere, and a
     * new device, as a renewal makes, starts with none.
     */
    fun refused(
        server: Server,
        device: ByteArray,
    ): String? = refusals()[refusalKey(server, device)]

    /** Every refusal kept, by [refusalKey]: for a screen to look up without the disk. */
    fun refusals(): Map<String, String> =
        prefs
            .getStringSet(REFUSED, null)
            .orEmpty()
            .mapNotNull { it.split('=', limit = 2).takeIf { p -> p.size == 2 }?.let { p -> p[0] to p[1] } }
            .toMap()

    /**
     * Keeps [server]'s refusal of [device]; with [since], a [generation],
     * not if [server] has been forgotten since, nor [device]'s refusals,
     * as [remember] does not.
     */
    fun markRefused(
        server: Server,
        device: ByteArray,
        code: String,
        since: Long? = null,
    ): Unit =
        synchronized(LOCK) {
            if (since != null && listOf(name("list", server), deviceName(device)).any { (forgottenAt[it] ?: 0) > since }) return
            val key = refusalKey(server, device)
            keepRefusals { it.filterNot { e -> e.startsWith("$key=") } + "$key=$code" }
        }

    /** Forgets [server]'s refusal of [device], for a login to try again. */
    fun forgetRefusal(
        server: Server,
        device: ByteArray,
    ): Unit =
        synchronized(LOCK) {
            val key = refusalKey(server, device)
            keepRefusals { it.filterNot { e -> e.startsWith("$key=") } }
        }

    /** Forgets every server's refusal of [device], once it is deleted or replaced; [at] as for [forget]. */
    fun forgetRefusalsOf(
        device: ByteArray,
        at: Long? = null,
    ): Unit =
        synchronized(LOCK) {
            forgotten(deviceName(device), at)
            val mine = "/" + shortHash(device) + "="
            keepRefusals { it.filterNot { e -> mine in e } }
        }

    /** Forgets every device's refusal by [server]. */
    fun forgetRefusals(server: Server): Unit =
        synchronized(LOCK) {
            val mine = name("refused", server) + "/"
            keepRefusals { it.filterNot { e -> e.startsWith(mine) } }
        }

    /** Where [device]'s forgets are counted, apart from any server's. */
    private fun deviceName(device: ByteArray) = "device-" + shortHash(device)

    private fun keepRefusals(change: (Set<String>) -> List<String>) =
        prefs.edit { putStringSet(REFUSED, change(prefs.getStringSet(REFUSED, null).orEmpty()).toSet()) }

    /**
     * Whether an account was named to link [server]'s identity to and the
     * server has not linked it yet: until it has, no login asks the server
     * to make an account in the named one's place.
     */
    fun linkAsked(server: Server): Boolean = name("link", server) in prefs.getStringSet(LINK_ASKED, null).orEmpty()

    fun askedToLink(
        server: Server,
        asked: Boolean,
        since: Long? = null,
    ): Unit =
        synchronized(LOCK) {
            // Not for a server forgotten since its login began.
            if (since != null && (forgottenAt[name("list", server)] ?: 0) > since) return
            val names = prefs.getStringSet(LINK_ASKED, null).orEmpty().toMutableSet()
            if (asked) names += name("link", server) else names -= name("link", server)
            prefs.edit { putStringSet(LINK_ASKED, names) }
        }

    private fun write(servers: List<Server>) {
        val list = JSONArray()
        for (s in servers) {
            val o = JSONObject().put(URL, s.url)
            s.login?.let { o.put(LOGIN, it) }
            (s.signIn as? SignIn.Identity)?.let { o.put(IDENTITY, it.fingerprint) }
            list.put(o)
        }
        prefs.edit { putString(SERVERS, list.toString()) }
    }

    /**
     * Forgets [server]'s password; with [since], a [generation], not one
     * kept since, by a newer login than the one that asked.
     */
    fun forgetPassword(
        server: Server,
        since: Long? = null,
    ): Unit =
        synchronized(LOCK) {
            if (keptSince(name("password", server), since)) return
            secrets.delete(name("password", server))
        }

    fun password(server: Server): String? = read(name("password", server))?.let { String(it) }

    fun session(server: Server): ByteArray? = read(name("session", server))

    /**
     * Forgets [server]'s session, and any write of one asked for before
     * this: a save on its way out does not bring it back. With [since], a
     * [generation], not one kept since, by a newer login than the one
     * that asked.
     */
    fun forgetSession(
        server: Server,
        since: Long? = null,
    ): Unit =
        synchronized(LOCK) {
            if (keptSince(name("session", server), since)) return
            forgotten(name("session", server), since)
            write(name("session", server), null)
        }

    /**
     * The session to resume [server] with, or with null none. A server
     * forgotten, or never saved, keeps none: a connection let go of may
     * still be saving its own on the way out. With [since], a
     * [generation], none if the session was forgotten since. False if it
     * could not be written now.
     */
    fun keepSession(
        server: Server,
        session: ByteArray?,
        since: Long? = null,
    ): Boolean =
        synchronized(LOCK) {
            if (since != null && (forgottenAt[name("session", server)] ?: 0) > since) return false
            val kept = session?.takeIf { server in all() }
            write(name("session", server), kept).also { if (it && kept != null) kept(name("session", server), since) }
        }

    /** [name] forgotten, by an act asked for [at] (now, if not said); under [LOCK]. */
    private fun forgotten(
        name: String,
        at: Long?,
    ) {
        forgottenAt[name] = maxOf(forgottenAt[name] ?: 0, at ?: ++forgets)
    }

    /** [name] kept, as [forgotten] is forgotten. */
    private fun kept(
        name: String,
        at: Long?,
    ) {
        keptAt[name] = maxOf(keptAt[name] ?: 0, at ?: ++forgets)
    }

    /** Whether [name] was kept after [since]: a clear asked for before it is not this one's. */
    private fun keptSince(
        name: String,
        since: Long?,
    ) = since != null && (keptAt[name] ?: 0) > since

    /** The one server this kept before it kept them all, and its secrets. */
    private fun forgetTheOneKeptBefore() {
        val url = prefs.getString(OLD_URL, null) ?: return
        val login = prefs.getString(OLD_LOGIN, null).orEmpty()
        for (kind in listOf("password", "session")) secrets.delete(kind + "-" + shortHash("$url\n$login".toByteArray()))
        prefs.edit {
            remove(OLD_URL)
            remove(OLD_LOGIN)
        }
    }

    /** A secret not written is one not kept: the caller carries on without it. */
    private fun write(
        name: String,
        secret: ByteArray?,
    ): Boolean =
        try {
            if (secret == null) secrets.delete(name) else secrets.put(name, secret)
            true
        } catch (_: SecretUnavailable) {
            false
        } catch (_: IOException) {
            false
        }

    private fun read(name: String): ByteArray? =
        try {
            secrets.get(name)
        } catch (_: SecretUnreadable) {
            secrets.delete(name)
            null
        } catch (_: SecretUnavailable) {
            null
        }

    private fun name(
        kind: String,
        server: Server,
    ) = nameOf(kind, server)

    private companion object {
        const val SERVERS = "servers"
        const val URL = "url"
        const val LOGIN = "login"
        const val IDENTITY = "identity"
        const val LINK_ASKED = "link_asked"
        const val REFUSED = "refused"

        /** One for the process: each change reads the list, then writes it whole. */
        val LOCK = Any()

        // The process's, under LOCK: a login outlives no process.
        var forgets = 0L
        val forgottenAt = HashMap<String, Long>()
        val keptAt = HashMap<String, Long>()

        /** Where the one server kept before was. */
        const val OLD_URL = "url"
        const val OLD_LOGIN = "login"
    }
}

/** A secret's name, from the server and how it is signed in to: never a file name a person typed. */
private fun nameOf(
    kind: String,
    server: Server,
): String {
    val whom =
        when (val s = server.signIn) {
            SignIn.Password -> server.login?.let { listOf("login", it) } ?: listOf("guest")
            is SignIn.Identity -> listOf("identity", s.fingerprint)
        }
    return kind + "-" + partsHash(listOf(server.url) + whom)
}

/** Where a refusal of [device] by [server] is kept, in [SavedServers.refusals]. */
fun refusalKey(
    server: Server,
    device: ByteArray,
): String = nameOf("refused", server) + "/" + shortHash(device)
