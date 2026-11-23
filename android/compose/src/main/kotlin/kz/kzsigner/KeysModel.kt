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
import kz.kzsigner.core.Checked
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.CoreException
import kz.kzsigner.core.Doc
import kz.kzsigner.core.DocKind
import kz.kzsigner.core.Keys
import kz.kzsigner.core.Nca
import kz.kzsigner.core.SignException
import kz.kzsigner.core.Signed
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.Vault
import kz.kzsigner.core.checkFile
import kz.kzsigner.core.inspect

/** A key file the owner picked or opened with the app. */
class KeyFile(val name: String, val bytes: ByteArray?)

/** A document to sign, read into memory, and what the core made of it. */
class DocFile(val name: String, val bytes: ByteArray, val info: Doc)

/** A file being checked; [original] is the document a detached .cms signs, once chosen. */
class CheckFile(val name: String, val bytes: ByteArray, val original: ByteArray? = null)

/** What a file opened with the app (or chosen on Home) turned out to be. */
enum class Opened { DOCUMENT, KEY, TOO_BIG, UNREADABLE }

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

    /**
     * "Sign a document" tapped with no key: Add key comes first and says so, and once the key
     * is added Home opens the document picker ([pickDocument]).
     */
    var signAfterAdd by mutableStateOf(false)

    /** Home opens the document picker once (after adding the key that signing needed). */
    var pickDocument by mutableStateOf(false)

    /** The document being signed: shared to the app, opened with it, or chosen on Home. */
    var document by mutableStateOf<DocFile?>(null)

    /** The document's signed copy, once signed. */
    var signed by mutableStateOf<Signed?>(null)

    /** The file on the Check screens, and what checking it found (null while checking). */
    var checking by mutableStateOf<CheckFile?>(null)
    var checked by mutableStateOf<Checked?>(null)

    /** NCA's servers; made on first use (it reads the bundled NCA certificates). */
    private val nca by lazy { Nca.kazakhstan() }

    /**
     * Who may issue a key to add: NCA and the CAs recognized in Kazakhstan. The emulator
     * tests' build (build type "uitest") also trusts its test CAs, from its assets, so its
     * test keys can be added; signing and checking still use [nca] alone.
     */
    private val issuers by lazy {
        if (BuildConfig.TEST_CAS) {
            val a = getApplication<Application>().assets
            Nca.withTestCas(a.list("testca").orEmpty().map { a.open("testca/$it").use { s -> s.readBytes() } })
        } else {
            nca
        }
    }

    init {
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                try {
                    // the vault file the earlier egui app wrote too: an update keeps the keys
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
            withContext(Dispatchers.IO) { v.addKey(issuers, file, password, prompt) }
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
    suspend fun read(uri: Uri): KeyFile = readFile(uri, MAX_KEY_FILE).key()

    /**
     * Reads a file opened with the app or chosen on Home: a key file goes to [incoming], a
     * document to [document].
     */
    suspend fun open(uri: Uri): Opened {
        val f = readFile(uri, MAX_DOCUMENT)
        val bytes = f.bytes ?: return if (f.tooBig) Opened.TOO_BIG else Opened.UNREADABLE
        val info = withContext(Dispatchers.Default) { inspect(f.name, bytes) }
        if (info.kind == DocKind.KEY) {
            incoming = KeyFile(f.name, bytes)
            return Opened.KEY
        }
        signed = null
        document = DocFile(f.name, bytes, info)
        return Opened.DOCUMENT
    }

    /** Reads a file chosen on Home's Check: it goes to [checking]. */
    suspend fun openForCheck(uri: Uri): Opened {
        val f = readFile(uri, MAX_DOCUMENT)
        val bytes = f.bytes ?: return if (f.tooBig) Opened.TOO_BIG else Opened.UNREADABLE
        checked = null
        checking = CheckFile(f.name, bytes)
        return Opened.DOCUMENT
    }

    /** Reads the document a detached .cms signs, and checks the two together. */
    suspend fun addOriginal(uri: Uri): Opened {
        val c = checking ?: return Opened.UNREADABLE
        val f = readFile(uri, MAX_DOCUMENT)
        val bytes = f.bytes ?: return if (f.tooBig) Opened.TOO_BIG else Opened.UNREADABLE
        checked = null
        checking = CheckFile(c.name, c.bytes, bytes)
        return Opened.DOCUMENT
    }

    /** Checks [checking] with NCA into [checked]. [lang]: the app's, for the details. */
    suspend fun check(lang: String) {
        val c = checking ?: return
        checked = null
        val r = withContext(Dispatchers.IO) { checkFile(nca, c.name, c.bytes, c.original, lang) }
        if (checking === c) checked = r
    }

    /** Checks the signatures already in a file about to be signed (the Sign screen's rows). */
    suspend fun checkQuietly(name: String, bytes: ByteArray, lang: String): Checked =
        withContext(Dispatchers.IO) { checkFile(nca, name, bytes, null, lang) }

    /** Goes from Check to Sign with the same file ("Add my signature", "Sign it myself"). */
    suspend fun signThis(name: String, bytes: ByteArray) {
        val info = withContext(Dispatchers.Default) { inspect(name, bytes) }
        signed = null
        document = DocFile(name, bytes, info)
    }

    /** Puts the document away (Done, or back from signing). */
    fun closeDocument() {
        document = null
        signed = null
    }

    /**
     * Signs [document] with key [keyId]: NCA checks the key first, then the phone asks for
     * the fingerprint or screen lock ([prompt]), or [password] opens a key kept under it.
     * [lang]: the app's language, for the PDF's stamp. Throws [SignException].
     */
    suspend fun sign(keyId: String, password: String?, prompt: ChipPrompt, lang: String): Signed {
        val v = vault ?: throw SignException.Failed("no key vault")
        val d = document ?: throw SignException.Failed("no document")
        val s = withContext(Dispatchers.IO) { v.sign(nca, keyId, d.name, d.bytes, password, prompt, lang) }
        signed = s
        return s
    }

    /** The phone has a working internet connection (else "No internet", not "NCA is down"). */
    fun online(): Boolean {
        val cm = getApplication<Application>().getSystemService(ConnectivityManager::class.java) ?: return false
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private class ReadFile(val name: String, val bytes: ByteArray?, val tooBig: Boolean) {
        fun key() = KeyFile(name, bytes)
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
                // InputStream.readNBytes is Android 13+: read in pieces, up to the limit
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                while (out.size() <= max) {
                    val n = s.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                }
                tooBig = out.size() > max
                if (tooBig) null else out.toByteArray()
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
