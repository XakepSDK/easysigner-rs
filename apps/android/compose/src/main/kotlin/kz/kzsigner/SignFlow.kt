package kz.kzsigner

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.withContext
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.Doc
import kz.kzsigner.core.SignException
import kz.kzsigner.core.Signed

/** A document to sign, read into memory, and what the core made of it. */
class DocFile(val name: String, val bytes: ByteArray, val info: Doc)

/**
 * The signing flow's state: the document, its signed copy, and the steps around adding the key
 * that signing needs. [io] runs the core's calls; [keys] is null until the vault is read (or when
 * it can't be).
 */
class SignFlow(private val docs: Documents, private val io: CoroutineContext, private val keys: () -> KeyStore?) {
    /** The document being signed: shared to the app, opened with it, or chosen on Home. */
    var document by mutableStateOf<DocFile?>(null)
        private set

    /** The document's signed copy, once signed. */
    var signed by mutableStateOf<Signed?>(null)
        private set

    /**
     * "Sign a document" tapped with no key: Add key comes first and says so, and once the key
     * is added Home opens the document picker ([pickDocument]).
     */
    var signAfterAdd by mutableStateOf(false)

    /** Home opens the document picker once (after adding the key that signing needed). */
    var pickDocument by mutableStateOf(false)

    /** Takes a document to sign, already inspected. */
    fun open(name: String, bytes: ByteArray, info: Doc) {
        signed = null
        document = DocFile(name, bytes, info)
    }

    /** Takes a document to sign, inspecting it first (from Check: "Add my signature"). */
    suspend fun open(name: String, bytes: ByteArray) {
        val info = withContext(io) { docs.inspect(name, bytes) }
        open(name, bytes, info)
    }

    /** Puts the document away (Done, or back from signing). */
    fun close() {
        document = null
        signed = null
    }

    /**
     * Signs [document] with key [keyId]: NCA checks the key first, then the phone asks for
     * the fingerprint or screen lock ([prompt]), or [password] opens a key kept under it.
     * [lang]: the app's language, for the PDF's stamp. Throws [SignException].
     */
    suspend fun sign(keyId: String, password: String?, prompt: ChipPrompt, lang: String): Signed {
        val k = keys() ?: throw SignException.Failed("no key vault")
        val d = document ?: throw SignException.Failed("no document")
        val s = withContext(io) { k.sign(keyId, d.name, d.bytes, password, prompt, lang) }
        signed = s
        return s
    }
}
