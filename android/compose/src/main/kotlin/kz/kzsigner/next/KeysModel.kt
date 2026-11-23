package kz.kzsigner.next

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kz.kzsigner.core.AddKeyException
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.CoreException
import kz.kzsigner.core.Keys
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.Vault

/** A key file the owner picked or opened with the app. */
class KeyFile(val name: String, val bytes: ByteArray?)

/** How adding a key went. */
sealed interface Added {
    data object Done : Added
    data object Cancelled : Added
    class Refused(val why: AddKeyException) : Added
}

/**
 * The saved keys, for every screen: the core's vault over the phone's chip. Every vault call
 * runs off the main thread, because the chip waits there for the fingerprint/PIN prompt.
 */
class KeysModel(app: Application) : AndroidViewModel(app) {
    val chip = KeystoreChip(app) { MainActivity.current() }
    private var vault: Vault? = null

    /** The keys, once read; null while reading. */
    var keys by mutableStateOf<Keys?>(null)
        private set

    /** The vault file can't be read. */
    var broken by mutableStateOf(false)
        private set

    /** What a key added now will open with. */
    var newKeyUnlock by mutableStateOf(Unlock.FINGERPRINT_OR_SCREEN_LOCK)
        private set

    /** The phone has a screen lock (else a new key opens with its password for that reason). */
    var screenLock by mutableStateOf(true)
        private set

    /** A key file opened with the app (Open with, Share), waiting for its password. */
    var incoming by mutableStateOf<KeyFile?>(null)

    init {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    // the vault file name the egui app uses (src/android.rs); this app has its
                    // own copy until it replaces that one (phase 6)
                    val v = Vault(File(app.filesDir, "keys.kzs").path, chip)
                    vault = v
                    val k = v.keys()
                    val u = v.newKeyUnlock()
                    val lock = chip.capabilities().screenLock
                    withContext(Dispatchers.Main) {
                        newKeyUnlock = u
                        screenLock = lock
                        keys = k
                    }
                } catch (e: CoreException) {
                    withContext(Dispatchers.Main) { broken = true }
                }
            }
        }
    }

    /** Asks the phone again what a new key will open with (a screen lock may have been set). */
    fun refresh() {
        val v = vault ?: return
        viewModelScope.launch {
            val (u, lock) = withContext(Dispatchers.IO) { v.newKeyUnlock() to chip.capabilities().screenLock }
            newKeyUnlock = u
            screenLock = lock
        }
    }

    /** Shows a hidden list (turned on in the egui app): one prompt. */
    suspend fun unlock(prompt: ChipPrompt) {
        val v = vault ?: return
        try {
            keys = withContext(Dispatchers.IO) { v.unlock(prompt) }
        } catch (e: CoreException) {
            // cancelled: the list stays hidden, with its button to try again
        }
    }

    suspend fun add(file: ByteArray, password: String, prompt: ChipPrompt): Added {
        val v = vault ?: return Added.Refused(AddKeyException.Failed("no key vault"))
        return try {
            withContext(Dispatchers.IO) { v.addKey(file, password, prompt) }
            keys = withContext(Dispatchers.IO) { v.keys() }
            Added.Done
        } catch (e: AddKeyException.Cancelled) {
            Added.Cancelled
        } catch (e: AddKeyException) {
            Added.Refused(e)
        }
    }

    suspend fun remove(id: String) {
        val v = vault ?: return
        try {
            withContext(Dispatchers.IO) { v.removeKey(id) }
        } catch (e: CoreException) {
            // already gone
        }
        keys = withContext(Dispatchers.IO) { v.keys() }
    }

    /** Reads a key file the owner chose (it is small: a .p12 is a few kilobytes). */
    suspend fun read(uri: Uri): KeyFile = withContext(Dispatchers.IO) {
        val app = getApplication<Application>()
        val name = try {
            app.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        } catch (e: Exception) {
            null
        } ?: uri.lastPathSegment ?: "?"
        val bytes = try {
            app.contentResolver.openInputStream(uri)?.use { s ->
                val b = s.readNBytes(MAX_KEY_FILE + 1)
                if (b.size > MAX_KEY_FILE) null else b
            }
        } catch (e: Exception) {
            null
        }
        KeyFile(name, bytes)
    }

    private companion object {
        /** Larger than any key file: anything bigger is not one. */
        const val MAX_KEY_FILE = 1 shl 20
    }
}
