package kz.kzsigner

import android.app.Application
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
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
import kz.kzsigner.core.DocKind
import kz.kzsigner.core.Keys
import kz.kzsigner.core.Nca
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.Vault

/** A key file the owner picked or opened with the app. */
class KeyFile(val name: String, val bytes: ByteArray?)

/** What a file opened with the app (or chosen on Home) turned out to be. */
enum class Opened { DOCUMENT, KEY, TOO_BIG, UNREADABLE }

/** How adding a key went. */
sealed interface Added {
    data object Done : Added
    data object Cancelled : Added
    class Refused(val why: AddKeyException) : Added
}

/**
 * The app's state, for every screen: the saved keys (the core's vault over the phone's chip),
 * the signing flow ([signing]) and the checking flow ([checking]). Every core call runs off the
 * main thread, because the chip waits there for the fingerprint/PIN prompt.
 */
class AppModel(app: Application) : AndroidViewModel(app) {
    val chip = KeystoreChip(app) { MainActivity.current() }
    private var store: KeyStore? = null

    /**
     * NCA's servers and the CAs recognized in Kazakhstan; made on first use (it reads the
     * bundled NCA certificates). The emulator tests' build (build type "uitest") uses fake
     * servers on the test machine instead (10.0.2.2, scripts/android-selftest.sh starts them)
     * and also trusts its test CAs, from its assets, so the whole app can be tested with test
     * keys.
     */
    private val nca by lazy {
        if (BuildConfig.TEST_CAS) {
            val a = getApplication<Application>().assets
            Nca.forTests(
                "http://10.0.2.2:18080/",
                "http://10.0.2.2:18081/",
                a.list("testca").orEmpty().map { a.open("testca/$it").use { s -> s.readBytes() } }
            )
        } else {
            Nca.kazakhstan()
        }
    }

    private val docs: Documents = NativeDocuments { nca }

    /** The document being signed, and its signed copy. */
    val signing = SignFlow(docs, Dispatchers.IO) { store }

    /** The file on the Check screens, and what checking it found. */
    val checking = CheckFlow(docs, Dispatchers.IO)

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
                    // the vault file the earlier egui app wrote too: an update keeps the keys
                    val v = NativeKeys(Vault(File(app.filesDir, "keys.kzs").path, chip)) { nca }
                    store = v
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
        val v = store ?: return
        viewModelScope.launch {
            val (u, lock) = withContext(Dispatchers.IO) { v.newKeyUnlock() to chip.capabilities().screenLock }
            newKeyUnlock = u
            screenLock = lock
        }
    }

    /** Shows a hidden list (turned on in the egui app): one prompt. */
    suspend fun unlock(prompt: ChipPrompt) {
        val v = store ?: return
        try {
            keys = withContext(Dispatchers.IO) { v.unlock(prompt) }
        } catch (e: CoreException) {
            // cancelled: the list stays hidden, with its button to try again
        }
    }

    suspend fun add(file: ByteArray, password: String, prompt: ChipPrompt): Added {
        val v = store ?: return Added.Refused(AddKeyException.Failed("no key vault"))
        return try {
            withContext(Dispatchers.IO) { v.add(file, password, prompt) }
            keys = withContext(Dispatchers.IO) { v.keys() }
            Added.Done
        } catch (e: AddKeyException.Cancelled) {
            Added.Cancelled
        } catch (e: AddKeyException) {
            Added.Refused(e)
        }
    }

    suspend fun remove(id: String) {
        val v = store ?: return
        try {
            withContext(Dispatchers.IO) { v.remove(id) }
        } catch (e: CoreException) {
            // already gone
        }
        keys = withContext(Dispatchers.IO) { v.keys() }
    }

    /** Reads a key file the owner chose (it is small: a .p12 is a few kilobytes). */
    suspend fun read(uri: Uri): KeyFile = readFile(uri, MAX_KEY_FILE).let { KeyFile(it.name, it.bytes) }

    /**
     * Reads a file opened with the app or chosen on Home: a key file goes to [incoming], a
     * document to [signing].
     */
    suspend fun open(uri: Uri): Opened {
        val f = readFile(uri, MAX_DOCUMENT)
        val bytes = f.bytes ?: return f.failure()
        val info = withContext(Dispatchers.Default) { docs.inspect(f.name, bytes) }
        if (info.kind == DocKind.KEY) {
            incoming = KeyFile(f.name, bytes)
            return Opened.KEY
        }
        signing.open(f.name, bytes, info)
        return Opened.DOCUMENT
    }

    /** Reads a file chosen on Home's Check: it goes to [checking]. */
    suspend fun openForCheck(uri: Uri): Opened {
        val f = readFile(uri, MAX_DOCUMENT)
        val bytes = f.bytes ?: return f.failure()
        checking.start(f.name, bytes)
        return Opened.DOCUMENT
    }

    /** Reads the document a detached .cms signs, to check the two together. */
    suspend fun addOriginal(uri: Uri): Opened {
        if (checking.file == null) return Opened.UNREADABLE
        val f = readFile(uri, MAX_DOCUMENT)
        val bytes = f.bytes ?: return f.failure()
        return if (checking.addOriginal(bytes)) Opened.DOCUMENT else Opened.UNREADABLE
    }

    /** The phone has a working internet connection (else "No internet", not "NCA is down"). */
    fun online(): Boolean = try {
        val cm = getApplication<Application>().getSystemService(ConnectivityManager::class.java)
        val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
        caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) ?: false
    } catch (e: SecurityException) {
        // can't tell: say NCA didn't answer rather than close the app
        true
    }

    private class ReadFile(val name: String, val bytes: ByteArray?, val tooBig: Boolean) {
        fun failure() = if (tooBig) Opened.TOO_BIG else Opened.UNREADABLE
    }

    private suspend fun readFile(uri: Uri, max: Int): ReadFile = withContext(Dispatchers.IO) {
        val app = getApplication<Application>()
        val name = try {
            app.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) c.getString(0) else null
            }
        } catch (e: Exception) {
            null
        } ?: uri.lastPathSegment ?: "?"
        var tooBig = false
        val bytes = try {
            app.contentResolver.openInputStream(uri)?.use { s ->
                Files.readAtMost(s, max).also { tooBig = it == null }
            }
        } catch (e: Exception) {
            null
        }
        ReadFile(name, bytes, tooBig)
    }

    private companion object {
        /** Larger than any key file: anything bigger is not one. */
        const val MAX_KEY_FILE = 1 shl 20

        /** The largest document signed on the phone: it is held in memory, twice. */
        const val MAX_DOCUMENT = 50 shl 20
    }
}
