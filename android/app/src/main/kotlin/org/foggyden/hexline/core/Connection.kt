package org.foggyden.hexline.core

/** The core's connection to one server, as the app holds it: one it closes when done. */
interface Connection :
    ServerConnectionInterface,
    AutoCloseable

/** A connection made by the core, to [url], telling [sink]. */
fun coreConnection(
    url: String,
    sink: UpdateSink,
): Connection = CoreConnection(ServerConnection(url, sink))

private class CoreConnection(
    private val connection: ServerConnection,
) : Connection,
    ServerConnectionInterface by connection {
    override fun close() = connection.close()
}
