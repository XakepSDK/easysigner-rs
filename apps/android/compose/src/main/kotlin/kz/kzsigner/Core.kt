package kz.kzsigner

import kz.kzsigner.core.Checked
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.Doc
import kz.kzsigner.core.Keys
import kz.kzsigner.core.Nca
import kz.kzsigner.core.Signed
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.Vault
import kz.kzsigner.core.checkFile

/**
 * What the flows ask of the core about documents. The app uses [NativeDocuments]; the JVM tests
 * use fakes, since the real one is the Rust library.
 */
interface Documents {
    /** What [bytes] (a file called [name]) is. */
    fun inspect(name: String, bytes: ByteArray): Doc

    /** Checks the signatures in [bytes], with NCA; [original]: a detached .cms's document. */
    fun check(name: String, bytes: ByteArray, original: ByteArray?, lang: String): Checked
}

/** The saved keys, as the flows use them. The app uses [NativeKeys]. */
interface KeyStore {
    fun keys(): Keys

    fun newKeyUnlock(): Unlock

    fun unlock(prompt: ChipPrompt): Keys

    fun add(file: ByteArray, password: String, prompt: ChipPrompt)

    fun remove(id: String)

    fun sign(keyId: String, name: String, bytes: ByteArray, password: String?, prompt: ChipPrompt, lang: String): Signed
}

class NativeDocuments(private val nca: () -> Nca) : Documents {
    override fun inspect(name: String, bytes: ByteArray): Doc = kz.kzsigner.core.inspect(name, bytes)

    override fun check(name: String, bytes: ByteArray, original: ByteArray?, lang: String): Checked =
        checkFile(nca(), name, bytes, original, lang)
}

class NativeKeys(private val vault: Vault, private val nca: () -> Nca) : KeyStore {
    override fun keys(): Keys = vault.keys()

    override fun newKeyUnlock(): Unlock = vault.newKeyUnlock()

    override fun unlock(prompt: ChipPrompt): Keys = vault.unlock(prompt)

    override fun add(file: ByteArray, password: String, prompt: ChipPrompt) {
        vault.addKey(nca(), file, password, prompt)
    }

    override fun remove(id: String) = vault.removeKey(id)

    override fun sign(keyId: String, name: String, bytes: ByteArray, password: String?, prompt: ChipPrompt, lang: String): Signed =
        vault.sign(nca(), keyId, name, bytes, password, prompt, lang)
}
