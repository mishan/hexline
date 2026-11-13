package org.foggyden.hexline.core

import android.content.Context

/** Hands the core's TLS verifier the app's context, before any connection. */
object Tls {
    init {
        System.loadLibrary("hexline_core")
    }

    @JvmStatic
    external fun init(context: Context)
}
