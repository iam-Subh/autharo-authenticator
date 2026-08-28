package app.autharo.authenticator

import io.flutter.app.FlutterApplication

/** Installs process-wide native stores before any Activity or FCM service. */
class AuthenticatorApplication : FlutterApplication() {
    override fun onCreate() {
        super.onCreate()
        NativeSessionBridge.installTokenStore(SyncTokenStore(applicationContext))
    }
}
