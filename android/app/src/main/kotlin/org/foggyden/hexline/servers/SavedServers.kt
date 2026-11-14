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

    /** Counts forgets: what [remember] is given to say when it was asked for. */
    fun generation(): Long = synchronized(LOCK) { forgets }

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
            true
        }

    /** [server] is forgotten whole, its secrets with it. */
    fun forget(server: Server): Unit =
        synchronized(LOCK) {
            forgottenAt[name("list", server)] = ++forgets
            write(all().filter { it != server })
            secrets.delete(name("password", server))
            secrets.delete(name("session", server))
            askedToLink(server, false)
        }

    /**
     * Whether an account was named to link [server]'s identity to and the
     * server has not linked it yet: until it has, no login asks the server
     * to make an account in the named one's place.
     */
    fun linkAsked(server: Server): Boolean = name("link", server) in prefs.getStringSet(LINK_ASKED, null).orEmpty()

    fun askedToLink(
        server: Server,
        asked: Boolean,
    ): Unit =
        synchronized(LOCK) {
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

    fun forgetPassword(server: Server) = secrets.delete(name("password", server))

    fun password(server: Server): String? = read(name("password", server))?.let { String(it) }

    fun session(server: Server): ByteArray? = read(name("session", server))

    /**
     * The session to resume [server] with, or with null none. A server
     * forgotten, or never saved, keeps none: a connection let go of may
     * still be saving its own on the way out. False if it could not be
     * written now.
     */
    fun keepSession(
        server: Server,
        session: ByteArray?,
    ): Boolean = synchronized(LOCK) { write(name("session", server), session?.takeIf { server in all() }) }

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

    /** A secret's name, from the server and how it is signed in to: never a file name a person typed. */
    private fun name(
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

    private companion object {
        const val SERVERS = "servers"
        const val URL = "url"
        const val LOGIN = "login"
        const val IDENTITY = "identity"
        const val LINK_ASKED = "link_asked"

        /** One for the process: each change reads the list, then writes it whole. */
        val LOCK = Any()

        // The process's, under LOCK: a login outlives no process.
        var forgets = 0L
        val forgottenAt = HashMap<String, Long>()

        /** Where the one server kept before was. */
        const val OLD_URL = "url"
        const val OLD_LOGIN = "login"
    }
}
