package dev.authcore.authenticator

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity

/**
 * PRD section 9.4: "Set FLAG_SECURE on Android to block screenshots and screen
 * recording."
 *
 * The flag is set before the Flutter view exists, so no frame can be captured
 * before it takes effect. It also blanks the entry in the recent-apps switcher,
 * which is the more common exposure: a code sitting in a task thumbnail
 * survives longer than any screenshot.
 */
class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        super.onCreate(savedInstanceState)
    }
}
