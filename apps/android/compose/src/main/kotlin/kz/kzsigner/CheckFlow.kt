package kz.kzsigner

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.withContext
import kz.kzsigner.core.Checked

/** A file being checked; [original] is the document a detached .cms signs, once chosen. */
class CheckFile(val name: String, val bytes: ByteArray, val original: ByteArray? = null)

/** The Check screens' state: the file, and what checking it found. [io] runs the core's calls. */
class CheckFlow(private val docs: Documents, private val io: CoroutineContext) {
    /** The file on the Check screens; null when none. */
    var file by mutableStateOf<CheckFile?>(null)
        private set

    /** What checking [file] found; null while checking. */
    var result by mutableStateOf<Checked?>(null)
        private set

    /** Starts checking a file anew. */
    fun start(name: String, bytes: ByteArray) {
        result = null
        file = CheckFile(name, bytes)
    }

    /** The document the detached .cms being checked signs; false when no file is being checked. */
    fun addOriginal(bytes: ByteArray): Boolean {
        val c = file ?: return false
        result = null
        file = CheckFile(c.name, c.bytes, bytes)
        return true
    }

    /** Checks [file] with NCA into [result]. [lang]: the app's, for the details. */
    suspend fun check(lang: String) {
        val c = file ?: return
        result = null
        val r = withContext(io) { docs.check(c.name, c.bytes, c.original, lang) }
        // the owner may have moved on to another file meanwhile
        if (file === c) result = r
    }

    /** Checks the signatures already in a file about to be signed (the Sign screen's rows). */
    suspend fun quietly(name: String, bytes: ByteArray, lang: String): Checked = withContext(io) { docs.check(name, bytes, null, lang) }

    fun close() {
        file = null
        result = null
    }
}
