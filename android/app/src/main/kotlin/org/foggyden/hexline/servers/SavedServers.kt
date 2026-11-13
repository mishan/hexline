package org.foggyden.hexline.servers

import android.content.Context
import android.content.SharedPreferences
import androidx.core.content.edit
import org.foggyden.hexline.secrets.SecretStore
import org.foggyden.hexline.secrets.SecretUnavailable
import org.foggyden.hexline.secrets.SecretUnreadable
import java.io.IOException
import java.security.MessageDigest

/** A server as the app connects to it: where, and as whom (null for a guest). */
data class Server(
    val url: String,
    val login: String?,
)

/**
 * The server the app last connected to. Its address and login are kept in
 * preferences; the password, when the person asked for it to be kept, and the
 * session to resume are secrets, in the [SecretStore].
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
    fun last(): Server? = prefs.getString(URL, null)?.let { Server(it, prefs.getString(LOGIN, null)) }

    /**
     * [server] is the last; its password is kept, or with null forgotten. The
     * one before it, if another, is forgotten whole: only the last is kept.
     * False if a secret could not be written now.
     */
    fun remember(
        server: Server,
        password: String?,
    ): Boolean {
        last()?.takeIf { it != server }?.let { old ->
            secrets.delete(name("password", old))
            secrets.delete(name("session", old))
        }
        prefs.edit {
            putString(URL, server.url)
            if (server.login == null) remove(LOGIN) else putString(LOGIN, server.login)
        }
        return write(name("password", server), password?.toByteArray())
    }

    fun forgetPassword(server: Server) = secrets.delete(name("password", server))

    fun password(server: Server): String? = read(name("password", server))?.let { String(it) }

    fun session(server: Server): ByteArray? = read(name("session", server))

    /** The session to resume [server] with, or with null none. False if it could not be written now. */
    fun keepSession(
        server: Server,
        session: ByteArray?,
    ): Boolean = write(name("session", server), session)

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

    /** A secret's name, from the server and login it is for: never a file name a person typed. */
    private fun name(
        kind: String,
        server: Server,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256").digest("${server.url}\n${server.login.orEmpty()}".toByteArray())
        return kind + "-" + digest.take(12).joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val URL = "url"
        const val LOGIN = "login"
    }
}
