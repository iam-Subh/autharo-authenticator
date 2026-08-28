package app.autharo.authenticator

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.KeyInfo
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
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
    // Kept for vaults written before authenticated wrapping used versioned
    // aliases. Those ciphertexts have no alias header.
    // Keep these legacy alias values after the application-ID rename. The
    // alias is stored inside existing wrapped-key ciphertext. Changing it
    // would make an existing local vault unreadable.
    private const val ALIAS = "dev.authcore.authenticator.vault_wrap_key"
    private const val ALIAS_PREFIX = "dev.authcore.authenticator.vault_wrap_key."
    private val WRAPPED_MAGIC = byteArrayOf(0x41, 0x4b, 0x53, 0x31) // AKS1
    private const val ALIAS_ID_LENGTH = 36

    /** GCM's standard nonce length. 12 bytes is the only size AES-GCM accepts here. */
    private const val NONCE_LENGTH = 12
    private const val TAG_LENGTH_BITS = 128

    /** Result of a wrap: the ciphertext and the nonce needed to open it. */
    data class Wrapped(val ciphertext: ByteArray, val nonce: ByteArray)

    /** A newly generated key and cipher that have not replaced the stored slot. */
    data class WrapRequest internal constructor(
        internal val alias: String,
        internal val cipher: Cipher,
    )

    /** A cipher and the ciphertext bytes that belong to its encoded alias. */
    data class OpenRequest internal constructor(
        internal val cipher: Cipher,
        internal val ciphertext: ByteArray,
    )

    /** True when this device already holds a wrapping key. */
    fun hasKey(): Boolean {
        val store = keystore()
        return store.containsAlias(ALIAS) ||
            store.aliases().toList().any { it.startsWith(ALIAS_PREFIX) }
    }

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
        val request = beginWrap(requireUserAuthentication)
        return finishWrap(request, request.cipher, plaintext)
    }

    /**
     * Creates a new wrapping key and an encryption cipher for it.
     *
     * A fresh alias keeps the key that protects the current stored slot. If
     * authentication is cancelled or encryption fails, the existing vault can
     * still open. The alias is encoded into the returned ciphertext after a
     * successful wrap, so no separate preference can disagree with it.
     */
    fun beginWrap(requireUserAuthentication: Boolean): WrapRequest {
        val alias = ALIAS_PREFIX + UUID.randomUUID().toString()
        val key = createKey(alias, requireUserAuthentication)
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            WrapRequest(alias, cipher)
        } catch (error: Throwable) {
            deleteAlias(alias)
            throw error
        }
    }

    fun finishWrap(
        request: WrapRequest,
        authorisedCipher: Cipher,
        plaintext: ByteArray,
    ): Wrapped = try {
        val ciphertext = authorisedCipher.doFinal(plaintext)
        Wrapped(encodeAlias(request.alias, ciphertext), authorisedCipher.iv)
    } catch (error: Throwable) {
        deleteAlias(request.alias)
        throw error
    }

    /** Removes a new key when its authentication prompt was cancelled. */
    fun cancelWrap(request: WrapRequest) {
        deleteAlias(request.alias)
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
        val request = beginOpen(ciphertext, nonce)
        return request.cipher.doFinal(request.ciphertext)
    }

    /**
     * Destroys the wrapping key (section 9.2.4, **Wipe this device**).
     *
     * After this the wrapped vault key is permanently unopenable, which is the
     * point. The caller still has to delete the records; ciphertext left on
     * disk is ciphertext an attacker can keep.
     */
    fun deleteKey() {
        val store = keystore()
        val aliases = store.aliases().toList()
        for (alias in aliases) {
            if (alias == ALIAS || alias.startsWith(ALIAS_PREFIX)) {
                store.deleteEntry(alias)
            }
        }
    }

    /**
     * Deletes versioned keys that no committed metadata slot references.
     *
     * The caller invokes this only after the new slot is committed. A failed
     * setup therefore cannot destroy the key for the current slot. Decode all
     * values before deletion so malformed input cannot cause a partial change.
     */
    fun retainOnly(ciphertexts: List<ByteArray>) {
        val retained = ciphertexts.mapTo(mutableSetOf()) { decodeAlias(it).alias }
        val store = keystore()
        val aliases = store.aliases().toList()
        for (alias in aliases) {
            if ((alias == ALIAS || alias.startsWith(ALIAS_PREFIX)) && alias !in retained) {
                store.deleteEntry(alias)
            }
        }
    }

    private const val TRANSFORMATION =
        "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/" +
            KeyProperties.ENCRYPTION_PADDING_NONE

    private fun keystore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    private fun existingKey(alias: String): SecretKey? =
        (keystore().getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey

    /**
     * Whether the stored key can only be used after the user authenticates.
     *
     * Read from the key itself, not from anything this app remembers. A
     * remembered flag can disagree with the key, and the key is what the
     * platform enforces.
     *
     * False when there is no key, or when it cannot be inspected: both lead to
     * the direct path, which fails with a readable message rather than raising
     * a biometric prompt for a key that would not accept one anyway.
     */
    fun requiresAuthentication(ciphertext: ByteArray): Boolean {
        val encoded = decodeAlias(ciphertext)
        val key = existingKey(encoded.alias) ?: return false
        return try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, PROVIDER)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            info.isUserAuthenticationRequired
        } catch (_: Exception) {
            false
        }
    }

    /**
     * A cipher ready to decrypt, for handing to `BiometricPrompt` as a
     * `CryptoObject`.
     *
     * Split out from [unwrap] because a key bound to per-use authentication
     * has to be *initialised* before the prompt and *used* after it — the
     * prompt is what authorises this particular cipher, and nothing else.
     */
    fun beginOpen(ciphertext: ByteArray, nonce: ByteArray): OpenRequest {
        require(nonce.size == NONCE_LENGTH) {
            "The stored nonce is ${nonce.size} bytes; AES-GCM here uses $NONCE_LENGTH."
        }
        val encoded = decodeAlias(ciphertext)
        val key = existingKey(encoded.alias)
            ?: throw IllegalStateException(
                "This device has no wrapping key. It was removed when the " +
                    "application's data was cleared, and the vault cannot be opened."
            )

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH_BITS, nonce))
        return OpenRequest(cipher, encoded.ciphertext)
    }

    private fun createKey(alias: String, requireUserAuthentication: Boolean): SecretKey {
        // StrongBox first, then the ordinary keystore. A device without the
        // hardware throws at generation time rather than reporting it up
        // front, so the fallback has to be a catch.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                return generate(alias, requireUserAuthentication, strongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                // Expected on most devices. Fall through.
            }
        }
        return generate(alias, requireUserAuthentication, strongBox = false)
    }

    private fun generate(
        alias: String,
        requireUserAuthentication: Boolean,
        strongBox: Boolean,
    ): SecretKey {
        val spec = KeyGenParameterSpec.Builder(
            alias,
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

    private data class EncodedCiphertext(
        val alias: String,
        val ciphertext: ByteArray,
    )

    private fun encodeAlias(alias: String, ciphertext: ByteArray): ByteArray {
        val id = alias.removePrefix(ALIAS_PREFIX).toByteArray(Charsets.US_ASCII)
        require(id.size == ALIAS_ID_LENGTH) { "The wrapping-key alias is invalid." }
        return WRAPPED_MAGIC + id + ciphertext
    }

    private fun decodeAlias(value: ByteArray): EncodedCiphertext {
        val headerLength = WRAPPED_MAGIC.size + ALIAS_ID_LENGTH
        if (value.size <= headerLength ||
            !value.copyOfRange(0, WRAPPED_MAGIC.size).contentEquals(WRAPPED_MAGIC)
        ) {
            return EncodedCiphertext(ALIAS, value)
        }

        val id = value.copyOfRange(WRAPPED_MAGIC.size, headerLength)
            .toString(Charsets.US_ASCII)
        val canonical = UUID.fromString(id).toString()
        require(canonical == id) { "The wrapping-key alias is invalid." }
        return EncodedCiphertext(
            ALIAS_PREFIX + canonical,
            value.copyOfRange(headerLength, value.size),
        )
    }

    private fun deleteAlias(alias: String) {
        val store = keystore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }
}
