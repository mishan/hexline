package org.foggyden.hexline.chat

import org.foggyden.hexline.servers.Server

/**
 * Whether a saved session refused with [code] is worth keeping: the server
 * was busy, not done with it (the core's own `for_now`).
 */
fun keepsSession(code: String): Boolean = code in PASSING

private val PASSING = setOf("rate_limited", "too_many_connections", "server_full", "server_error")

/**
 * The login to connect as. A saved session with no password to log in
 * again goes as nobody, so if it has lapsed the core refuses it as expired
 * rather than trying the account with no password, which the server would
 * count as a failed login.
 */
fun loginFor(
    server: Server,
    password: String?,
    saved: ByteArray?,
): String? = if (saved != null && password == null) null else server.login
