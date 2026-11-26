package kz.kzsigner

import java.io.ByteArrayInputStream
import java.io.InputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class FilesTest {
    @Test
    fun safeKeepsOrdinaryNames() {
        assertEquals("Договор №5.pdf.cms", Files.safe("Договор №5.pdf.cms"))
        assertEquals("a b.txt", Files.safe("a b.txt"))
    }

    @Test
    fun safeCannotLeaveTheFolder() {
        for (bad in listOf("../../etc/passwd", "..\\..\\x", "/abs/path", "C:\\x", "a/../b")) {
            val s = Files.safe(bad)
            assertFalse(s, s.contains('/') || s.contains('\\') || s.contains(':'))
            assertFalse(s, s.startsWith("."))
        }
        assertEquals("_.._etc_passwd", Files.safe("../../etc/passwd"))
    }

    @Test
    fun safeReplacesReservedAndControlCharacters() {
        assertEquals("a_b_c_d_e_f_g_h", Files.safe("a*b?c\"d<e>f|g\u0001h"))
    }

    @Test
    fun safeNeverGivesAnEmptyOrDotName() {
        assertEquals("document", Files.safe(""))
        assertEquals("document", Files.safe(".."))
        assertEquals("document", Files.safe(" . "))
        assertEquals("x", Files.safe(" .x. "))
    }

    @Test
    fun mimeOfSignatures() {
        assertEquals("application/pkcs7-signature", Files.mime("a.pdf.cms"))
        assertEquals("application/pkcs7-signature", Files.mime("A.P7S"))
        assertEquals("application/pkcs7-signature", Files.mime("a.sig"))
        assertEquals("application/pkcs7-mime", Files.mime("a.p7m"))
        assertEquals("text/xml", Files.mime("a.xml"))
    }

    @Test
    fun mimeOfOtherFilesFromThePhonesList() {
        val asked = mutableListOf<String>()
        val list = { ext: String ->
            asked += ext
            if (ext == "pdf") "application/pdf" else null
        }
        assertEquals("application/pdf", Files.mime("Договор.PDF", list))
        assertEquals("application/octet-stream", Files.mime("a.unknown", list))
        assertEquals("application/octet-stream", Files.mime("no-extension", list))
        assertEquals(listOf("pdf", "unknown", ""), asked)
    }

    @Test
    fun readAtMostTakesUpToTheLimit() {
        val max = 20_000
        for (n in listOf(0, 1, 8191, 8192, 8193, max - 1, max)) {
            val data = ByteArray(n) { (it % 251).toByte() }
            assertArrayEquals("$n bytes", data, Files.readAtMost(ByteArrayInputStream(data), max))
        }
        for (n in listOf(max + 1, max + 8192, 3 * max)) {
            assertNull("$n bytes", Files.readAtMost(ByteArrayInputStream(ByteArray(n)), max))
        }
        assertArrayEquals(ByteArray(0), Files.readAtMost(ByteArrayInputStream(ByteArray(0)), 0))
        assertNull(Files.readAtMost(ByteArrayInputStream(ByteArray(1)), 0))
    }

    @Test
    fun readAtMostReadsNoMoreThanItNeeds() {
        for (max in listOf(0, 10, 8191, 8192, 10_000, 3 * 8192)) {
            val s = CountingStream(1_000_000)
            assertNull(Files.readAtMost(s, max))
            assertEquals("one byte past $max", max + 1, s.taken)
        }
    }

    /** [size] zero bytes, counting what was read. */
    private class CountingStream(private val size: Int) : InputStream() {
        var taken = 0

        override fun read(): Int = if (taken < size) 0.also { taken++ } else -1

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (taken >= size) return -1
            val n = minOf(len, size - taken)
            taken += n
            return n
        }
    }
}
