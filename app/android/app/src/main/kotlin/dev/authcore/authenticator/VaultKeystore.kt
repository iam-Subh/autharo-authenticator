package dev.authcore.authenticator

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The wrapping key for the device slot (PRD section 9.2.4).
 *
 * Section 9.2.4 step 2: "Generate a wrapping key inside the platform keystore.
 * Mark it non-exportable."
 *
 * `KeyGenerator` with an `AndroidKeyStore` provider produces a key that lives
 * inside the keystore and cannot be read back out — `SecretKey.getEncoded()`
 * returns null for it. Only `wrap` and `unwrap` below can use it, and only
 * while this application is installed. That is the property the device slot
 * depends on, and it is also why the wrapping cannot be done in Rust: there is
 * no key material to hand over.
 *
 * Section 9.4: "Android Keystore, StrongBox when present." StrongBox is a
 * separate security chip and is preferred where the device has one, with a
 * fall back to the ordinary keystore where it does not.
 *
 * # What this does not survive
 *
 * The key is destroyed when the application is uninstalled, when the user
 * clears its data, and on some devices when the screen lock is removed. In
 * every case the wrapped vault key in `meta.db` becomes permanently
 * unopenable. That is the intended behaviour for a local-only vault — there is
 * nowhere else the key could have been kept without weakening it — and it is
 * the reason section 9.2.4 warns that a local-only vault cannot be restored.
 */
object VaultKeystore {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "dev.authcore.authenticator.vault_wrap_key"

    /** GCM's standard nonce length. 12 bytes is the only size AES-GCM accepts here. */
    private const val NONCE_LENGTH = 12
    private const val TAG_LENGTH_BITS = 128

    /** Result of a wrap: the ciphertext and the nonce needed to open it. */
    data class Wrapped(val ciphertext: ByteArray, val nonce: ByteArray)

    /** True when this device already holds a wrapping key. */
    fun hasKey(): Boolean = keystore().containsAlias(ALIAS)

    /**
     * Encrypts [plaintext] with the device's wrapping key, creating that key
     * on first use.
     *
     * [requireUserAuthentication] binds the key to a biometric or device
     * credential check (section 9.4: "Bind the key to biometric authentication
     * when the user enables it"). A key created with it cannot be used until
     * the user has authenticated, which is what turns the lock into key
     * release rather than screen hiding.
     */
    fun wrap(plaintext: ByteArray, requireUserAuthentication: Boolean): Wrapped {
        val key = existingKey() ?: createKey(requireUserAuthentication)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val ciphertext = cipher.doFinal(plaintext)
        return Wrapped(ciphertext, cipher.iv)
    }

    /**
     * Decrypts what [wrap] produced.
     *
     * Throws if the key is gone, if the ciphertext was altered, or if the key
     * requires an authentication that has not happened. The caller must not
     * turn any of those into an empty result: a failed unwrap that looks like
     * success would hand a zero-length key to the record cipher.
     */
    fun unwrap(ciphertext: ByteArray, nonce: ByteArray): ByteArray {
        require(nonce.size == NONCE_LENGTH) {
            "The stored nonce is ${nonce.size} bytes; AES-GCM here uses $NONCE_LENGTH."
        }
        val key = existingKey()
            ?: throw IllegalStateException(
                "This device has no wrapping key. It was removed when the " +
                    "application's data was cleared, and the vault cannot be opened."
            )

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH_BITS, nonce))
        return cipher.doFinal(ciphertext)
    }

    /**
     * Destroys the wrapping key (section 9.2.4, **Wipe this device**).
     *
     * After this the wrapped vault key is permanently unopenable, which is the
     * point. The caller still has to delete the records; ciphertext left on
     * disk is ciphertext an attacker can keep.
     */
    fun deleteKey() {
        val keystore = keystore()
        if (keystore.containsAlias(ALIAS)) {
            keystore.deleteEntry(ALIAS)
        }
    }

    private const val TRANSFORMATION =
        "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/" +
            KeyProperties.ENCRYPTION_PADDING_NONE

    private fun keystore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun existingKey(): SecretKey? =
        (keystore().getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey

    private fun createKey(requireUserAuthentication: Boolean): SecretKey {
        // StrongBox first, then the ordinary keystore. A device without the
        // hardware throws at generation time rather than reporting it up
        // front, so the fallback has to be a catch.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generate(requireUserAuthentication, strongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                // Expected on most devices. Fall through.
            }
        }
        return generate(requireUserAuthentication, strongBox = false)
    }

    private fun generate(requireUserAuthentication: Boolean, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // A caller-supplied nonce would let the same nonce be reused under
            // one key, which breaks GCM outright. Letting the keystore pick it
            // makes that mistake impossible rather than merely discouraged.
            .setRandomizedEncryptionRequired(true)
            .apply {
                if (requireUserAuthentication) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            /* timeout = */ 0,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(-1)
                    }
                    // Without this, enrolling a new fingerprint would silently
                    // widen who can open the vault.
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        setInvalidatedByBiometricEnrollment(true)
                    }
                }
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        generator.init(spec)
        return generator.generateKey()
    }
}
