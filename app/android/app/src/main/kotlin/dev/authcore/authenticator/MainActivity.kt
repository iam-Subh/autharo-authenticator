package dev.authcore.authenticator

import android.os.Bundle
import android.view.WindowManager
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * PRD section 9.4: "Set FLAG_SECURE on Android to block screenshots and screen
 * recording."
 *
 * The flag is set before the Flutter view exists, so no frame can be captured
 * before it takes effect. It also blanks the entry in the recent-apps switcher,
 * which is the more common exposure: a code sitting in a task thumbnail
 * survives longer than any screenshot.
 *
 * The activity also hosts the keystore channel. [VaultKeystore] has to run on
 * this side of the boundary because a non-exportable Android Keystore key
 * cannot be handed to Rust — see section 9.2.4 and the note on
 * `begin_device_setup` in the bridge.
 */
class MainActivity : FlutterActivity() {
    private companion object {
        const val CHANNEL = "dev.authcore.authenticator/keystore"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "hasKey" -> result.success(VaultKeystore.hasKey())

                        "wrap" -> {
                            val plaintext = call.argument<ByteArray>("plaintext")
                                ?: return@setMethodCallHandler result.error(
                                    "missing_argument",
                                    "wrap needs 'plaintext'",
                                    null,
                                )
                            val requireAuth =
                                call.argument<Boolean>("requireUserAuthentication") ?: false

                            val wrapped = VaultKeystore.wrap(plaintext, requireAuth)
                            // Overwrite the copy this side holds. It does not
                            // reach the copy Dart passed in, which is why the
                            // Dart caller wipes its own buffer as well.
                            plaintext.fill(0)

                            result.success(
                                mapOf(
                                    "ciphertext" to wrapped.ciphertext,
                                    "nonce" to wrapped.nonce,
                                ),
                            )
                        }

                        "unwrap" -> {
                            val ciphertext = call.argument<ByteArray>("ciphertext")
                            val nonce = call.argument<ByteArray>("nonce")
                            if (ciphertext == null || nonce == null) {
                                return@setMethodCallHandler result.error(
                                    "missing_argument",
                                    "unwrap needs 'ciphertext' and 'nonce'",
                                    null,
                                )
                            }
                            result.success(VaultKeystore.unwrap(ciphertext, nonce))
                        }

                        "deleteKey" -> {
                            VaultKeystore.deleteKey()
                            result.success(null)
                        }

                        else -> result.notImplemented()
                    }
                } catch (error: Throwable) {
                    // Never swallow a keystore failure. A failed unwrap that
                    // returned success would hand an empty key to the record
                    // cipher, and every entry would silently fail to decrypt.
                    result.error(
                        "keystore_failure",
                        error.message ?: error::class.java.simpleName,
                        null,
                    )
                }
            }
    }
}
