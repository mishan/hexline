package org.foggyden.hexline.chat

import org.foggyden.hexline.core.ClassicLogin
import org.foggyden.hexline.identity.StoredIdentity
import org.foggyden.hexline.identity.standing
import org.foggyden.hexline.identity.usable
import org.foggyden.hexline.servers.Server
import org.foggyden.hexline.servers.SignIn

/** What the connect screen asks the app to connect with. */
data class ConnectRequest(
    val server: Server,
    val password: String?,
    val remember: Boolean,
    val link: ClassicLogin?,
)

/**
 * The connect screen's form, as the person has filled it in. Whatever was
 * typed for one server's account (a password, an account to link) is
 * dropped as soon as the form turns to another server, so it is never
 * sent to, or kept for, a server it was not typed for.
 */
data class ConnectForm(
    val url: String = "",
    val byIdentity: Boolean = false,
    val login: String = "",
    val password: String = "",
    val rememberPassword: Boolean = false,
    /** The identity picked, by fingerprint: null until one is. */
    val chosen: String? = null,
    val linking: Boolean = false,
    val linkLogin: String = "",
    val linkPassword: String = "",
) {
    fun withUrl(url: String): ConnectForm = if (url == this.url) this else typedForgotten().copy(url = url)

    /** The form as [server] was saved: its address and how it signs in. */
    fun filled(server: Server): ConnectForm =
        when (val how = server.signIn) {
            SignIn.Password -> typedForgotten().copy(url = server.url, byIdentity = false, login = server.login.orEmpty())
            is SignIn.Identity -> typedForgotten().copy(url = server.url, byIdentity = true, chosen = how.fingerprint)
        }

    private fun typedForgotten() = copy(password = "", rememberPassword = false, linking = false, linkLogin = "", linkPassword = "")

    /**
     * The identity to sign in as: the one picked, while this phone still
     * keeps it, or with none picked the only one there is. One picked and
     * gone is never stood in for by another: the person picks again.
     */
    fun identity(identities: List<StoredIdentity>): StoredIdentity? =
        if (chosen != null) identities.find { it.fingerprint == chosen } else identities.singleOrNull()

    /** The identity picked is no longer on this phone. */
    fun missing(identities: List<StoredIdentity>): Boolean = chosen != null && identities.none { it.fingerprint == chosen }

    /** The server as an identity signs in to it from this form. */
    fun identityServer(identity: StoredIdentity) = Server(url.trim(), null, SignIn.Identity(identity.fingerprint))

    /**
     * What to connect with, or null while the form is not ready: with an
     * identity whose certificate is outside its time, or that this server
     * refused (as [refused] says), it is not.
     */
    fun request(
        identities: List<StoredIdentity>,
        now: Long,
        refused: (Server, StoredIdentity) -> String?,
    ): ConnectRequest? {
        if (url.isBlank()) return null
        if (!byIdentity) {
            return ConnectRequest(
                Server(url.trim(), login.ifBlank { null }),
                password.ifEmpty { null },
                rememberPassword,
                null,
            )
        }
        val identity = identity(identities) ?: return null
        val server = identityServer(identity)
        if (!standing(identity, now).usable || refused(server, identity) != null) return null
        val link =
            if (linking) {
                ClassicLogin(linkLogin.ifBlank { return null }, linkPassword)
            } else {
                null
            }
        return ConnectRequest(server, null, false, link)
    }
}
