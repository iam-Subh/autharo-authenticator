package app.autharo.authenticator

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import android.os.SystemClock
import android.view.WindowManager
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * PRD section 9.4: "Set FLAG_SECURE on Android to block screenshots and screen
 * recording."
 *
 * The stored screenshot policy is applied before the Flutter view exists. The
 * secure default blocks capture until the user explicitly permits it. Blocking
 * also blanks the entry in the recent-apps switcher.
 *
 * The activity also hosts the keystore channel. [VaultKeystore] has to run on
 * this side of the boundary because a non-exportable Android Keystore key
 * cannot be handed to Rust. [NativeVaultBridge] transfers protected bytes
 * directly between Kotlin and Rust. Dart receives only one-time handles.
 *
 * # Why this extends FlutterFragmentActivity and not FlutterActivity
 *
 * FR-32's biometric unlock goes through `local_auth`, which on Android is
 * `androidx.biometric.BiometricPrompt`. That prompt is a Fragment, so it can
 * only be shown from a `FragmentActivity` — and Flutter's default
 * `FlutterActivity` is not one.
 *
 * With the default, pressing "Use biometrics" fails at the platform channel
 * with "the current activity must be a FragmentActivity" and no prompt ever
 * appears. Nothing in Dart, Rust, or the build catches it: the code is correct,
 * the plugin is correct, and the only wrong thing is which Android class this
 * file names. It has to be found on a device, by pressing the button.
 *
 * `FlutterFragmentActivity` is Flutter's own drop-in for exactly this, and it
 * needs no theme change — `FragmentActivity` works with a plain framework
 * theme; it is `AppCompatActivity` that would demand an AppCompat one.
 */
class MainActivity : FlutterFragmentActivity() {
    private companion object {
        const val CHANNEL = "app.autharo.authenticator/keystore"
        const val CLOCK_CHANNEL = "app.autharo.authenticator/clock"
        const val SCREEN_CAPTURE_CHANNEL = "app.autharo.authenticator/screen_capture"
        const val APPEARANCE_CHANNEL = "app.autharo.authenticator/appearance"
        const val CLIPBOARD_CHANNEL = "app.autharo.authenticator/clipboard"
        const val AUTOMATIC_BACKUP_CHANNEL =
            "app.autharo.authenticator/automatic_backup"
        const val HOME_WIDGET_CHANNEL = "app.autharo.authenticator/home_widget"
        const val PASSKEY_CHANNEL = "app.autharo.authenticator/passkey"
        const val DEVICE_INTEGRITY_CHANNEL = "app.autharo.authenticator/device_integrity"
        const val DEVICE_IDENTITY_CHANNEL = "app.autharo.authenticator/device_identity"
        const val CHOOSE_BACKUP_DIRECTORY = 7001
        const val SECURITY_PREFERENCES = "security_preferences"
        const val BLOCK_SCREENSHOTS = "block_screenshots"
        const val ROOT_POLICY = "root_policy"
    }

    private var pendingBackupDirectoryResult: MethodChannel.Result? = null
    private val automaticBackupStore by lazy {
        AutomaticBackupStore(applicationContext)
    }
    private lateinit var passkeyBridge: PasskeyCredentialBridge

    override fun onCreate(savedInstanceState: Bundle?) {
        // Apply the stored choice before Flutter creates its first frame. The
        // default is true, so an existing installation stays protected until
        // the user explicitly permits screenshots.
        val blockScreenshots = getSharedPreferences(
            SECURITY_PREFERENCES,
            MODE_PRIVATE,
        ).getBoolean(BLOCK_SCREENSHOTS, true)
        setScreenshotBlocking(blockScreenshots)
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        passkeyBridge = PasskeyCredentialBridge(this)

        // FR-33: "Read a monotonic clock that counts across device sleep, such
        // as SystemClock.elapsedRealtime() on Android."
        //
        // Three clocks are available and only this one is correct here.
        // `System.currentTimeMillis` is the wall clock, which the user can set
        // backwards. `System.nanoTime` maps to CLOCK_MONOTONIC, which stops
        // while the device is in deep sleep — a phone locked in a pocket
        // overnight would come back as though no time had passed.
        // `elapsedRealtime` maps to CLOCK_BOOTTIME and keeps counting.
        //
        // It resets to zero on reboot, which is why the Dart side treats a
        // value lower than the stored one as expired.
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CLOCK_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "elapsedRealtime" -> result.success(SystemClock.elapsedRealtime())
                    else -> result.notImplemented()
                }
            }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            APPEARANCE_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "dynamicSeed" -> {
                    val colour = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        getColor(android.R.color.system_accent1_500)
                    } else {
                        null
                    }
                    result.success(colour)
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            DEVICE_IDENTITY_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "description" -> {
                    val manufacturer = Build.MANUFACTURER.trim()
                    val model = Build.MODEL.trim()
                    val name = if (
                        manufacturer.isNotEmpty() &&
                        !model.startsWith(manufacturer, ignoreCase = true)
                    ) {
                        "$manufacturer $model"
                    } else {
                        model
                    }.trim().take(100)
                    result.success(
                        mapOf(
                            "name" to name.ifEmpty { "Android device" },
                            "platform" to "android",
                        ),
                    )
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            DEVICE_INTEGRITY_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "getPolicy" -> result.success(
                    getSharedPreferences(SECURITY_PREFERENCES, MODE_PRIVATE)
                        .getString(ROOT_POLICY, "warn"),
                )
                "setPolicy" -> {
                    val policy = call.argument<String>("policy")
                    if (policy !in setOf("ignore", "warn", "block")) {
                        return@setMethodCallHandler result.error(
                            "invalid_policy",
                            "The root policy is invalid",
                            null,
                        )
                    }
                    val stored = getSharedPreferences(SECURITY_PREFERENCES, MODE_PRIVATE)
                        .edit()
                        .putString(ROOT_POLICY, policy)
                        .commit()
                    if (stored) result.success(null) else result.error(
                        "preference_failure",
                        "The root policy could not be stored",
                        null,
                    )
                }
                "check" -> {
                    val assessment = DeviceIntegrityDetector.forCurrentDevice().evaluate()
                    result.success(
                        mapOf(
                            "evaluated" to assessment.evaluated,
                            "indicators" to assessment.indicators,
                        ),
                    )
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            SCREEN_CAPTURE_CHANNEL,
        ).setMethodCallHandler { call, result ->
            when (call.method) {
                "isBlocked" -> result.success(isScreenshotBlockingEnabled())
                "setBlocked" -> {
                    val blocked = call.argument<Boolean>("blocked")
                        ?: return@setMethodCallHandler result.error(
                            "missing_argument",
                            "setBlocked needs 'blocked'",
                            null,
                        )
                    val stored = getSharedPreferences(
                        SECURITY_PREFERENCES,
                        MODE_PRIVATE,
                    )
                        .edit()
                        .putBoolean(BLOCK_SCREENSHOTS, blocked)
                        .commit()
                    if (!stored) {
                        return@setMethodCallHandler result.error(
                            "preference_failure",
                            "The screenshot setting could not be stored",
                            null,
                        )
                    }
                    setScreenshotBlocking(blocked)
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            CLIPBOARD_CHANNEL,
        ).setMethodCallHandler { call, result ->
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            when (call.method) {
                "copySensitive" -> {
                    val text = call.argument<String>("text")
                        ?: return@setMethodCallHandler result.error(
                            "missing_argument",
                            "copySensitive needs 'text'",
                            null,
                        )
                    val clip = ClipData.newPlainText("Authenticator secret", text)
                    clip.description.extras = PersistableBundle().apply {
                        // Android 13 uses this flag to hide the clipboard
                        // preview. Earlier supported versions also recognize
                        // this compatibility key.
                        putBoolean("android.content.extra.IS_SENSITIVE", true)
                    }
                    clipboard.setPrimaryClip(clip)
                    result.success(null)
                }
                "clearIfEquals" -> {
                    val expected = call.argument<String>("expected")
                        ?: return@setMethodCallHandler result.error(
                            "missing_argument",
                            "clearIfEquals needs 'expected'",
                            null,
                        )
                    val current = clipboard.primaryClip
                        ?.takeIf { it.itemCount > 0 }
                        ?.getItemAt(0)
                        ?.coerceToText(this)
                        ?.toString()
                    if (current == expected) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            clipboard.clearPrimaryClip()
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                    }
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            AUTOMATIC_BACKUP_CHANNEL,
        ).setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "status" -> {
                        val location = automaticBackupStore.configuredLocation()
                        result.success(
                            mapOf(
                                "configured" to (location != null),
                                "location" to location?.let(::displayTreeLocation),
                            ),
                        )
                    }
                    "chooseDirectory" -> chooseBackupDirectory(result)
                    "clearDirectory" -> {
                        automaticBackupStore.clearDirectory()
                        result.success(null)
                    }
                    "writeBackup" -> {
                        val name = call.argument<String>("name")
                            ?: return@setMethodCallHandler result.error(
                                "missing_argument",
                                "writeBackup needs 'name'",
                                null,
                            )
                        val text = call.argument<String>("text")
                            ?: return@setMethodCallHandler result.error(
                                "missing_argument",
                                "writeBackup needs 'text'",
                                null,
                            )
                        val keep = call.argument<Int>("keep") ?: 7
                        automaticBackupStore.write(name, text, keep)
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            } catch (error: Throwable) {
                result.error(
                    "automatic_backup_failure",
                    error.message ?: error::class.java.simpleName,
                    null,
                )
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            HOME_WIDGET_CHANNEL,
        ).setMethodCallHandler { call, result ->
            try {
                when (call.method) {
                    "status" -> {
                        val configuration = HomeWidgetStore.read(applicationContext)
                        result.success(
                            mapOf(
                                "enabled" to configuration.enabled,
                                "entryId" to configuration.entryId,
                                "title" to configuration.title,
                            ),
                        )
                    }
                    "configure" -> {
                        val enabled = call.argument<Boolean>("enabled") ?: false
                        HomeWidgetStore.write(
                            applicationContext,
                            enabled,
                            call.argument("entryId"),
                            call.argument("title"),
                        )
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            } catch (error: Throwable) {
                result.error(
                    "home_widget_failure",
                    error.message ?: error::class.java.simpleName,
                    null,
                )
            }
        }

        MethodChannel(
            flutterEngine.dartExecutor.binaryMessenger,
            PASSKEY_CHANNEL,
        ).setMethodCallHandler { call, result ->
            val requestJson = call.argument<String>("requestJson")
                ?: return@setMethodCallHandler result.error(
                    "missing_argument",
                    "${call.method} needs requestJson",
                    null,
                )
            when (call.method) {
                "create" -> passkeyBridge.create(requestJson, result)
                "get" -> passkeyBridge.get(requestJson, result)
                else -> result.notImplemented()
            }
        }

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "hasKey" -> result.success(VaultKeystore.hasKey())

                        "wrapHandle" -> {
                            val handle = call.argument<ByteArray>("handle")
                                ?: return@setMethodCallHandler result.error(
                                    "missing_argument",
                                    "wrapHandle needs 'handle'",
                                    null,
                                )
                            val requireAuth =
                                call.argument<Boolean>("requireUserAuthentication") ?: false

                            if (requireAuth) {
                                wrapHandleAfterAuthentication(handle, result)
                            } else {
                                val plaintext = NativeVaultBridge.takeSecret(handle)
                                try {
                                    val wrapped = VaultKeystore.wrap(plaintext, false)
                                    result.success(wrapped.asChannelValue())
                                } finally {
                                    plaintext.fill(0)
                                }
                            }
                        }

                        "unwrapToHandle" -> {
                            val ciphertext = call.argument<ByteArray>("ciphertext")
                            val nonce = call.argument<ByteArray>("nonce")
                            if (ciphertext == null || nonce == null) {
                                return@setMethodCallHandler result.error(
                                    "missing_argument",
                                    "unwrapToHandle needs 'ciphertext' and 'nonce'",
                                    null,
                                )
                            }
                            if (VaultKeystore.requiresAuthentication(ciphertext)) {
                                unwrapToHandleAfterAuthentication(ciphertext, nonce, result)
                            } else {
                                returnSecretHandle(
                                    VaultKeystore.unwrap(ciphertext, nonce),
                                    result,
                                )
                            }
                        }

                        "deleteKey" -> {
                            VaultKeystore.deleteKey()
                            result.success(null)
                        }

                        "retainOnly" -> {
                            val ciphertexts = call.argument<List<ByteArray>>("ciphertexts")
                                ?: return@setMethodCallHandler result.error(
                                    "missing_argument",
                                    "retainOnly needs 'ciphertexts'",
                                    null,
                                )
                            VaultKeystore.retainOnly(ciphertexts)
                            result.success(null)
                        }

                        else -> result.notImplemented()
                    }
                } catch (error: Throwable) {
                    // Never swallow a keystore failure. A failed unwrap that
                    // returned success would hand an empty key to the record
                    // cipher, and every entry would silently fail to decrypt.
                    NativeVaultBridge.cancelPendingOperation()
                    result.error(
                        "keystore_failure",
                        error.message ?: error::class.java.simpleName,
                        null,
                    )
                }
            }
    }

    override fun onDestroy() {
        // Activity recreation invalidates platform-channel callbacks. Remove
        // handles that Dart can no longer complete and wipe their secrets.
        NativeVaultBridge.cancelPendingOperation()
        pendingBackupDirectoryResult?.error(
            "activity_destroyed",
            "The backup directory picker was closed",
            null,
        )
        pendingBackupDirectoryResult = null
        if (::passkeyBridge.isInitialized) passkeyBridge.close()
        super.onDestroy()
    }

    @Deprecated("Android uses this callback for ACTION_OPEN_DOCUMENT_TREE")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != CHOOSE_BACKUP_DIRECTORY) return

        val pending = pendingBackupDirectoryResult ?: return
        pendingBackupDirectoryResult = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) {
            pending.success(null)
            return
        }
        try {
            automaticBackupStore.saveDirectory(uri)
            pending.success(displayTreeLocation(uri))
        } catch (error: Throwable) {
            pending.error(
                "automatic_backup_failure",
                error.message ?: error::class.java.simpleName,
                null,
            )
        }
    }

    private fun chooseBackupDirectory(result: MethodChannel.Result) {
        if (pendingBackupDirectoryResult != null) {
            result.error(
                "directory_picker_busy",
                "A backup directory picker is already open",
                null,
            )
            return
        }
        pendingBackupDirectoryResult = result
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or
                    Intent.FLAG_GRANT_PREFIX_URI_PERMISSION,
            )
        }
        try {
            startActivityForResult(intent, CHOOSE_BACKUP_DIRECTORY)
        } catch (error: Throwable) {
            pendingBackupDirectoryResult = null
            result.error(
                "directory_picker_failure",
                error.message ?: error::class.java.simpleName,
                null,
            )
        }
    }

    private fun displayTreeLocation(uri: Uri): String =
        Uri.decode(uri.lastPathSegment ?: uri.toString())

    private fun setScreenshotBlocking(blocked: Boolean) {
        if (blocked) {
            window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE,
            )
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }

    private fun isScreenshotBlockingEnabled(): Boolean =
        window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0

    /**
     * Authenticates the encryption operation used when biometric protection is
     * enabled. Authentication must authorise this exact cipher. Calling
     * `doFinal` before the prompt causes `IllegalBlockSizeException` on Android
     * Keystore providers.
     */
    private fun wrapHandleAfterAuthentication(
        handle: ByteArray,
        result: MethodChannel.Result,
    ) {
        val request = try {
            VaultKeystore.beginWrap(requireUserAuthentication = true)
        } catch (error: Throwable) {
            NativeVaultBridge.discardSecret(handle)
            NativeVaultBridge.cancelPendingOperation()
            return result.error(
                "keystore_failure",
                error.message ?: error::class.java.simpleName,
                null,
            )
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authenticated: BiometricPrompt.AuthenticationResult,
                ) {
                    val authorised = authenticated.cryptoObject?.cipher
                    if (authorised == null) {
                        VaultKeystore.cancelWrap(request)
                        NativeVaultBridge.discardSecret(handle)
                        NativeVaultBridge.cancelPendingOperation()
                        result.error(
                            "keystore_failure",
                            "the authentication returned no cipher",
                            null,
                        )
                        return
                    }
                    val plaintext = try {
                        NativeVaultBridge.takeSecret(handle)
                    } catch (error: Throwable) {
                        VaultKeystore.cancelWrap(request)
                        NativeVaultBridge.cancelPendingOperation()
                        result.error(
                            "keystore_failure",
                            error.message ?: error::class.java.simpleName,
                            null,
                        )
                        return
                    }
                    try {
                        val wrapped = VaultKeystore.finishWrap(
                            request,
                            authorised,
                            plaintext,
                        )
                        result.success(wrapped.asChannelValue())
                    } catch (error: Throwable) {
                        NativeVaultBridge.cancelPendingOperation()
                        result.error(
                            "keystore_failure",
                            error.message ?: error::class.java.simpleName,
                            null,
                        )
                    } finally {
                        plaintext.fill(0)
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    VaultKeystore.cancelWrap(request)
                    NativeVaultBridge.discardSecret(handle)
                    NativeVaultBridge.cancelPendingOperation()
                    result.error("authentication_cancelled", message.toString(), null)
                }
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Protect your authenticator")
            .setSubtitle("Authenticate to protect the vault key")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()

        try {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(request.cipher))
        } catch (error: Throwable) {
            VaultKeystore.cancelWrap(request)
            NativeVaultBridge.discardSecret(handle)
            NativeVaultBridge.cancelPendingOperation()
            result.error(
                "keystore_failure",
                error.message ?: error::class.java.simpleName,
                null,
            )
        }
    }

    private fun VaultKeystore.Wrapped.asChannelValue(): Map<String, ByteArray> =
        mapOf("ciphertext" to ciphertext, "nonce" to nonce)

    /**
     * FR-32: opens a key that is bound to per-use authentication.
     *
     * # Why a plain biometric check is not enough
     *
     * The key is generated with `setUserAuthenticationParameters(timeout = 0)`,
     * which means the platform authorises *one cipher*, not a period of time.
     * Authenticating separately and then decrypting does not satisfy it: the
     * cipher has to be handed to `BiometricPrompt` as a `CryptoObject` and used
     * again afterwards, and only that instance is authorised.
     *
     * Getting this wrong does not fail safe or loudly. It surfaces as
     * `IllegalBlockSizeException` from `doFinal` — a message that says nothing
     * about authentication and reads exactly like a corrupted vault. That is
     * what a user saw, and for a moment it looked like their codes were gone.
     * They were not: the key and the data were intact, and only the way the key
     * was being used was wrong.
     *
     * Both authenticators are allowed because the key was generated accepting
     * both. A device with no enrolled fingerprint must still open with its PIN
     * or pattern, or turning biometrics on would lock the vault away the moment
     * a fingerprint was removed.
     */
    private fun unwrapToHandleAfterAuthentication(
        ciphertext: ByteArray,
        nonce: ByteArray,
        result: MethodChannel.Result,
    ) {
        val request = try {
            VaultKeystore.beginOpen(ciphertext, nonce)
        } catch (error: Throwable) {
            NativeVaultBridge.cancelPendingOperation()
            return result.error(
                "keystore_failure",
                error.message ?: error::class.java.simpleName,
                null,
            )
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    authenticated: BiometricPrompt.AuthenticationResult,
                ) {
                    // The cipher from the result, not the one above. They are
                    // the same instance today; taking it from the result is
                    // what the API guarantees, and it is the authorised one.
                    val authorised = authenticated.cryptoObject?.cipher
                    if (authorised == null) {
                        NativeVaultBridge.cancelPendingOperation()
                        result.error(
                            "keystore_failure",
                            "the authentication returned no cipher",
                            null,
                        )
                        return
                    }
                    try {
                        returnSecretHandle(
                            authorised.doFinal(request.ciphertext),
                            result,
                        )
                    } catch (error: Throwable) {
                        NativeVaultBridge.cancelPendingOperation()
                        result.error(
                            "keystore_failure",
                            error.message ?: error::class.java.simpleName,
                            null,
                        )
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    // A distinct code, because cancelling is not a failure. The
                    // Dart side shows the PIN field rather than an error when
                    // somebody dismisses the prompt.
                    NativeVaultBridge.cancelPendingOperation()
                    result.error("authentication_cancelled", message.toString(), null)
                }

                // onAuthenticationFailed is deliberately not overridden: a
                // single unrecognised finger is not the end of the attempt, and
                // the prompt lets the user try again. Replying here would
                // resolve the channel while the prompt is still on screen.
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock your authenticator")
            .setSubtitle("Your codes stay encrypted until you do")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL,
            )
            .build()

        try {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(request.cipher))
        } catch (error: Throwable) {
            NativeVaultBridge.cancelPendingOperation()
            result.error(
                "keystore_failure",
                error.message ?: error::class.java.simpleName,
                null,
            )
        }
    }

    /** Gives unwrapped bytes directly to Rust and returns only their handle. */
    private fun returnSecretHandle(
        plaintext: ByteArray,
        result: MethodChannel.Result,
    ) {
        try {
            result.success(NativeVaultBridge.storeSecret(plaintext))
        } finally {
            // Rust also wipes the JNI byte-array input after copying it. Wipe
            // the Kotlin owner as a separate copy can exist on this side.
            plaintext.fill(0)
        }
    }
}
