package kz.kzsigner

import kotlin.coroutines.EmptyCoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kz.kzsigner.core.Checked
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.Doc
import kz.kzsigner.core.DocKind
import kz.kzsigner.core.Keys
import kz.kzsigner.core.Output
import kz.kzsigner.core.SignException
import kz.kzsigner.core.Signed
import kz.kzsigner.core.Unlock
import kz.kzsigner.core.Verdict
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

private fun doc(kind: DocKind = DocKind.PDF) = Doc(kind, null, null, emptyList(), Output.INSIDE_PDF, false, "a-signed.pdf")

private fun checked(name: String, verdict: Verdict = Verdict.VALID) = Checked(verdict, null, emptyList(), name, null, null)

/** The core's document calls, answered from memory; records what was asked. */
private class FakeDocuments : Documents {
    val asked = mutableListOf<String>()
    var gate: CompletableDeferred<Unit>? = null
    var during: () -> Unit = {}

    override fun inspect(name: String, bytes: ByteArray): Doc {
        asked += "inspect $name"
        return doc()
    }

    override fun check(name: String, bytes: ByteArray, original: ByteArray?, lang: String): Checked {
        asked += "check $name ${bytes.size} ${original?.size} $lang"
        during()
        gate?.let { runBlocking { it.await() } }
        return checked(name)
    }
}

private class FakeKeys : KeyStore {
    val signedWith = mutableListOf<String>()

    override fun keys() = Keys(emptyList(), false)

    override fun newKeyUnlock() = Unlock.FINGERPRINT_OR_SCREEN_LOCK

    override fun unlock(prompt: ChipPrompt) = keys()

    override fun add(file: ByteArray, password: String, prompt: ChipPrompt) = Unit

    override fun remove(id: String) = Unit

    override fun sign(keyId: String, name: String, bytes: ByteArray, password: String?, prompt: ChipPrompt, lang: String): Signed {
        signedWith += "$keyId $name ${bytes.size} $password $lang"
        return Signed(bytes + 1, "$name.cms", 1L, false)
    }
}

private val prompt = ChipPrompt("t", "s", "d")

class CheckFlowTest {
    @Test
    fun checksTheFileWithItsOriginal() = runBlocking {
        val docs = FakeDocuments()
        val f = CheckFlow(docs, EmptyCoroutineContext)
        f.check("en")
        assertTrue("nothing to check", docs.asked.isEmpty())
        assertFalse("no file: no original", f.addOriginal(byteArrayOf(1)))

        f.start("a.cms", byteArrayOf(1, 2))
        assertNull(f.result)
        f.check("kk")
        assertEquals(listOf("check a.cms 2 null kk"), docs.asked)
        assertEquals("a.cms", f.result?.documentName)

        assertTrue(f.addOriginal(byteArrayOf(9, 9, 9)))
        assertNull("checked anew", f.result)
        assertEquals("a.cms", f.file?.name)
        assertArrayEquals(byteArrayOf(1, 2), f.file?.bytes)
        f.check("ru")
        assertEquals("check a.cms 2 3 ru", docs.asked.last())

        // checking again: no stale result while it runs
        var whileChecking: Checked? = checked("stale")
        docs.during = { whileChecking = f.result }
        f.check("en")
        assertNull(whileChecking)
        assertEquals("a.cms", f.result?.documentName)

        // another file: the last result goes
        f.start("b.pdf", byteArrayOf(5))
        assertNull(f.result)
        assertEquals("b.pdf", f.file?.name)
        assertNull(f.file?.original)
        f.check("en")
        assertEquals("b.pdf", f.result?.documentName)

        f.close()
        assertNull(f.file)
        assertNull(f.result)
    }

    @Test
    fun aResultForAnEarlierFileIsDropped() = runBlocking {
        val docs = FakeDocuments()
        val f = CheckFlow(docs, Dispatchers.Default)
        f.start("old.pdf", byteArrayOf(1))
        val gate = CompletableDeferred<Unit>()
        docs.gate = gate
        val run = async(start = CoroutineStart.UNDISPATCHED) { f.check("en") }
        f.start("new.pdf", byteArrayOf(2))
        gate.complete(Unit)
        run.await()
        assertNull("old.pdf's answer is not new.pdf's", f.result)
        assertEquals("new.pdf", f.file?.name)
    }

    @Test
    fun quietlyLeavesTheScreenAlone() = runBlocking {
        val docs = FakeDocuments()
        val f = CheckFlow(docs, EmptyCoroutineContext)
        assertEquals("x.pdf", f.quietly("x.pdf", byteArrayOf(1), "en").documentName)
        assertNull(f.file)
        assertNull(f.result)
    }
}

class SignFlowTest {
    @Test
    fun signsTheDocumentShown() = runBlocking {
        val keys = FakeKeys()
        val f = SignFlow(FakeDocuments(), EmptyCoroutineContext) { keys }
        f.open("a.pdf", byteArrayOf(1, 2, 3), doc())
        val s = f.sign("k1", null, prompt, "kk")
        assertEquals(listOf("k1 a.pdf 3 null kk"), keys.signedWith)
        assertSame(s, f.signed)
        assertEquals("a.pdf.cms", s.name)

        // another document: the signed copy goes
        f.open("b.xml", byteArrayOf(4), doc(DocKind.XML))
        assertNull(f.signed)
        f.sign("k2", "pw", prompt, "ru")
        assertEquals("k2 b.xml 1 pw ru", keys.signedWith.last())

        f.close()
        assertNull(f.document)
        assertNull(f.signed)
    }

    @Test
    fun addingAKeyFirst() {
        val f = SignFlow(FakeDocuments(), EmptyCoroutineContext) { null }
        assertFalse(f.signAfterAdd || f.pickDocument)
        f.signAfterAdd = true
        f.pickDocument = true
        assertTrue(f.signAfterAdd && f.pickDocument)
    }

    @Test
    fun opensFromCheckByInspecting() = runBlocking {
        val docs = FakeDocuments()
        val f = SignFlow(docs, EmptyCoroutineContext) { null }
        f.open("c.cms", byteArrayOf(7))
        assertEquals(listOf("inspect c.cms"), docs.asked)
        assertEquals("c.cms", f.document?.name)
        assertEquals(DocKind.PDF, f.document?.info?.kind)
    }

    @Test
    fun refusesWithoutAVaultOrADocument() = runBlocking {
        val noVault = SignFlow(FakeDocuments(), EmptyCoroutineContext) { null }
        noVault.open("a.pdf", byteArrayOf(1), doc())
        expectFailed("no key vault") { noVault.sign("k", null, prompt, "en") }
        assertNull(noVault.signed)

        val noDoc = SignFlow(FakeDocuments(), EmptyCoroutineContext) { FakeKeys() }
        expectFailed("no document") { noDoc.sign("k", null, prompt, "en") }
    }

    private suspend fun expectFailed(why: String, run: suspend () -> Unit) {
        try {
            run()
            fail("signed")
        } catch (e: SignException.Failed) {
            assertEquals(why, e.detail)
        }
    }
}
