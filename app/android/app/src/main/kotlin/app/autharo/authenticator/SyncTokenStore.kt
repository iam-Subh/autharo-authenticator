package app.autharo.authenticator

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores the synchronization access/refresh pair outside `meta.db`.
 *
 * The file contains only AES-GCM ciphertext. The AES key is non-exportable and
 * remains in Android Keystore. The key does not require biometric approval, so
 * a scheduled synchronization cycle can run while the application vault is
 * locked.
 *
 * The file is in [Context.getNoBackupFilesDir]. Android must not restore
 * ciphertext without the device-local Keystore key that opens it.
 */
class SyncTokenStore(context: Context) {
    private val sessionFile = AtomicFile(
        File(context.applicationContext.noBackupFilesDir, FILE_NAME),
    )
    private val pageKeyFile = AtomicFile(
        File(context.applicationContext.noBackupFilesDir, PAGE_KEY_FILE_NAME),
    )
    private val lock = Any()

    fun hasSession(): Boolean = synchronized(lock) {
        sessionFile.baseFile.isFile
    }

    /**
     * Returns the versioned access/refresh payload to Rust.
     *
     * Rust clears the returned Java byte array immediately after it copies the
     * value into a zeroed-on-use native buffer.
     */
    fun readSession(): ByteArray? = synchronized(lock) {
        if (!sessionFile.baseFile.isFile) return@synchronized null

        val stored = try {
            sessionFile.readFully()
        } catch (error: Exception) {
            throw IllegalStateException("The encrypted synchronization session could not be read.", error)
        }

        try {
            val sealed = decode(stored)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                existingKey(KEY_ALIAS) ?: throw IllegalStateException(
                    "The device key for the synchronization session is missing.",
                ),
                GCMParameterSpec(TAG_LENGTH_BITS, sealed.iv),
            )
            cipher.doFinal(sealed.ciphertext)
        } catch (error: Exception) {
            throw IllegalStateException("The encrypted synchronization session could not be opened.", error)
        } finally {
            stored.fill(0)
        }
    }

    /** Saves both rotated tokens as one atomic value. */
    fun writeSession(payload: ByteArray) {
        try {
            require(payload.isNotEmpty() && payload.size <= MAX_PAYLOAD_BYTES) {
                "The synchronization session has an invalid length."
            }

            synchronized(lock) {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(KEY_ALIAS))
                val ciphertext = cipher.doFinal(payload)
                val stored = encode(cipher.iv, ciphertext)
                try {
                    writeAtomically(sessionFile, stored)
                } finally {
                    stored.fill(0)
                    ciphertext.fill(0)
                }
            }
        } finally {
            // JNI created this byte array only for this call. Clear it before
            // control returns to Rust.
            payload.fill(0)
        }
    }

    /** Removes the session and then its dedicated Keystore key. */
    fun clearSession() = synchronized(lock) {
        // Delete the ciphertext first. A crash before key deletion leaves an
        // unused key. Reversing the order could leave undecryptable state that
        // still looks signed in.
        sessionFile.delete()
        val store = keyStore()
        if (store.containsAlias(KEY_ALIAS)) {
            store.deleteEntry(KEY_ALIAS)
        }
    }

    /** Returns the page-encryption key used by locked synchronization. */
    fun readOrCreatePageKey(): ByteArray = synchronized(lock) {
        if (pageKeyFile.baseFile.isFile) {
            val stored = pageKeyFile.readFully()
            try {
                val sealed = decode(stored)
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    existingKey(PAGE_KEY_ALIAS) ?: throw IllegalStateException(
                        "The device key for the vault page key is missing.",
                    ),
                    GCMParameterSpec(TAG_LENGTH_BITS, sealed.iv),
                )
                return@synchronized cipher.doFinal(sealed.ciphertext).also {
                    require(it.size == PAGE_KEY_BYTES) {
                        "The vault page key has an invalid length."
                    }
                }
            } finally {
                stored.fill(0)
            }
        }

        val pageKey = ByteArray(PAGE_KEY_BYTES)
        SecureRandom().nextBytes(pageKey)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(PAGE_KEY_ALIAS))
        val ciphertext = cipher.doFinal(pageKey)
        val stored = encode(cipher.iv, ciphertext)
        try {
            writeAtomically(pageKeyFile, stored)
            pageKey
        } catch (error: Exception) {
            pageKey.fill(0)
            throw error
        } finally {
            stored.fill(0)
            ciphertext.fill(0)
        }
    }

    /** Deletes the page key after Rust has removed the local vault. */
    fun clearPageKey() = synchronized(lock) {
        pageKeyFile.delete()
        val store = keyStore()
        if (store.containsAlias(PAGE_KEY_ALIAS)) {
            store.deleteEntry(PAGE_KEY_ALIAS)
        }
    }

    private fun writeAtomically(file: AtomicFile, value: ByteArray) {
        val output = file.startWrite()
        try {
            output.write(value)
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw IllegalStateException("The encrypted synchronization session could not be saved.", error)
        }
    }

    private fun getOrCreateKey(alias: String): SecretKey {
        existingKey(alias)?.let { return it }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER,
        )
        val specification = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            // This key protects a background synchronization credential. It
            // must remain distinct from the biometric-gated vault key.
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(specification)
        return generator.generateKey()
    }

    private fun existingKey(alias: String): SecretKey? =
        (keyStore().getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private data class SealedSession(
        val iv: ByteArray,
        val ciphertext: ByteArray,
    )

    private fun encode(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == IV_LENGTH_BYTES) { "The AES-GCM IV has an invalid length." }
        return ByteBuffer.allocate(FILE_HEADER_BYTES + iv.size + ciphertext.size)
            .put(FILE_MAGIC)
            .put(FILE_VERSION)
            .put(iv.size.toByte())
            .put(iv)
            .put(ciphertext)
            .array()
    }

    private fun decode(stored: ByteArray): SealedSession {
        require(stored.size >= FILE_HEADER_BYTES + IV_LENGTH_BYTES + TAG_LENGTH_BYTES) {
            "The encrypted synchronization session is truncated."
        }
        val buffer = ByteBuffer.wrap(stored)
        val magic = ByteArray(FILE_MAGIC.size)
        buffer.get(magic)
        require(magic.contentEquals(FILE_MAGIC)) {
            "The encrypted synchronization session has an invalid header."
        }
        require(buffer.get() == FILE_VERSION) {
            "The encrypted synchronization session uses an unsupported version."
        }
        val ivLength = buffer.get().toInt() and 0xff
        require(ivLength == IV_LENGTH_BYTES && buffer.remaining() >= ivLength + TAG_LENGTH_BYTES) {
            "The encrypted synchronization session has an invalid IV."
        }
        val iv = ByteArray(ivLength)
        buffer.get(iv)
        val ciphertext = ByteArray(buffer.remaining())
        buffer.get(ciphertext)
        return SealedSession(iv, ciphertext)
    }

    private companion object {
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val KEY_ALIAS = "authcore.sync.session.v1"
        const val PAGE_KEY_ALIAS = "authcore.sync.page_key.v1"
        const val FILE_NAME = "sync_session_v1.bin"
        const val PAGE_KEY_FILE_NAME = "sync_page_key_v1.bin"
        const val PAGE_KEY_BYTES = 32
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LENGTH_BYTES = 12
        const val TAG_LENGTH_BITS = 128
        const val TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8
        const val MAX_PAYLOAD_BYTES = 16 * 1024
        val FILE_MAGIC = byteArrayOf(0x41, 0x54, 0x53, 0x46) // ATSF
        const val FILE_VERSION: Byte = 1
        const val FILE_HEADER_BYTES = 4 + 1 + 1
    }
}
