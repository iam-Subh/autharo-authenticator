package dev.authcore.authenticator

import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Runs passkey user-interface operations through Android Credential Manager.
 * The server creates and verifies all WebAuthn JSON. This class does not parse,
 * change, or accept a credential response.
 */
class PasskeyCredentialBridge(
    private val activity: FlutterFragmentActivity,
) {
    private val manager = CredentialManager.create(activity)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    fun create(requestJson: String, result: MethodChannel.Result) {
        if (requestJson.isBlank()) {
            result.error("missing_argument", "create needs requestJson", null)
            return
        }
        scope.launch {
            try {
                val response = manager.createCredential(
                    activity,
                    CreatePublicKeyCredentialRequest(requestJson),
                )
                val passkey = response as? CreatePublicKeyCredentialResponse
                    ?: return@launch result.error(
                        "passkey_response",
                        "Credential Manager returned a different credential type",
                        null,
                    )
                result.success(passkey.registrationResponseJson)
            } catch (error: Throwable) {
                result.error(
                    "passkey_create_failure",
                    error.message ?: error::class.java.simpleName,
                    null,
                )
            }
        }
    }

    fun get(requestJson: String, result: MethodChannel.Result) {
        if (requestJson.isBlank()) {
            result.error("missing_argument", "get needs requestJson", null)
            return
        }
        scope.launch {
            try {
                val response = manager.getCredential(
                    activity,
                    GetCredentialRequest(
                        listOf(GetPublicKeyCredentialOption(requestJson)),
                    ),
                )
                val passkey = response.credential as? PublicKeyCredential
                    ?: return@launch result.error(
                        "passkey_response",
                        "Credential Manager returned a different credential type",
                        null,
                    )
                result.success(passkey.authenticationResponseJson)
            } catch (error: Throwable) {
                result.error(
                    "passkey_get_failure",
                    error.message ?: error::class.java.simpleName,
                    null,
                )
            }
        }
    }

    fun close() {
        scope.cancel()
    }
}
