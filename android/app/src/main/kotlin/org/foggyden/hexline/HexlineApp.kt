package org.foggyden.hexline

import android.app.Application
import org.foggyden.hexline.core.Tls

class HexlineApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Tls.init(this)
    }
}
