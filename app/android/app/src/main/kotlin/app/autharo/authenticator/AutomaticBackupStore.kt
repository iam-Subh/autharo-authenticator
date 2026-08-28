package app.autharo.authenticator

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract

/** Writes encrypted backup text to a user-selected document tree. */
class AutomaticBackupStore(private val context: Context) {
    private companion object {
        const val PREFERENCES = "automatic_backup_preferences"
        const val TREE_URI = "tree_uri"
        const val FILE_PREFIX = "authenticator-auto-"
    }

    private val resolver = context.contentResolver
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun configuredLocation(): Uri? = preferences.getString(TREE_URI, null)?.let(Uri::parse)

    fun saveDirectory(uri: Uri) {
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
            Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        resolver.takePersistableUriPermission(uri, flags)
        check(preferences.edit().putString(TREE_URI, uri.toString()).commit()) {
            "The backup directory could not be stored"
        }
    }

    fun clearDirectory() {
        val uri = configuredLocation()
        if (uri != null) {
            try {
                resolver.releasePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                )
            } catch (_: SecurityException) {
                // The system can already have removed the grant.
            }
        }
        check(preferences.edit().remove(TREE_URI).commit()) {
            "The backup directory setting could not be removed"
        }
    }

    fun write(name: String, text: String, keep: Int) {
        require(name.startsWith(FILE_PREFIX) && name.endsWith(".json")) {
            "The backup file name is invalid"
        }
        require(keep in 1..30) { "The backup retention count is invalid" }

        val tree = configuredLocation()
            ?: error("Choose an automatic backup directory first")
        val existing = children(tree)
        val target = existing.firstOrNull { it.name == name }?.uri
            ?: DocumentsContract.createDocument(
                resolver,
                tree,
                "application/json",
                name,
            ) ?: error("The backup file could not be created")

        resolver.openOutputStream(target, "wt").use { stream ->
            checkNotNull(stream) { "The backup file could not be opened" }
            stream.write(text.toByteArray(Charsets.UTF_8))
            stream.flush()
        }

        val afterWrite = children(tree)
            .filter { it.name.startsWith(FILE_PREFIX) && it.name.endsWith(".json") }
            .sortedByDescending { it.name }
        for (old in afterWrite.drop(keep)) {
            DocumentsContract.deleteDocument(resolver, old.uri)
        }
    }

    private fun children(tree: Uri): List<ChildDocument> {
        val documentId = DocumentsContract.getTreeDocumentId(tree)
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(
            tree,
            documentId,
        )
        val projection = arrayOf(
            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        )
        val children = mutableListOf<ChildDocument>()
        resolver.query(childrenUri, projection, null, null, null).use { cursor ->
            checkNotNull(cursor) { "The backup directory could not be read" }
            val idColumn = cursor.getColumnIndexOrThrow(
                DocumentsContract.Document.COLUMN_DOCUMENT_ID,
            )
            val nameColumn = cursor.getColumnIndexOrThrow(
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
            )
            while (cursor.moveToNext()) {
                val id = cursor.getString(idColumn)
                children += ChildDocument(
                    name = cursor.getString(nameColumn),
                    uri = DocumentsContract.buildDocumentUriUsingTree(tree, id),
                )
            }
        }
        return children
    }

    private data class ChildDocument(val name: String, val uri: Uri)
}
