package kz.kzsigner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
}
