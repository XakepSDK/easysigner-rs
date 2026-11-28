package kz.kzsigner

import android.graphics.Bitmap
import android.os.Looper
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kz.kzsigner.core.Chip
import kz.kzsigner.core.ChipCaps
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.ChipSecurity
import kz.kzsigner.core.ChipUnlock
import kz.kzsigner.core.KeyInfo
import kz.kzsigner.core.Nca
import kz.kzsigner.core.Vault
import kz.kzsigner.core.Visit
import kz.kzsigner.ui.KzsignerTheme
import kz.kzsigner.ui.MeetScreen
import kz.kzsigner.ui.VisitScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

/** The phone's chip, in software: AES-GCM keys in memory. */
private class SoftChip : Chip {
    private val keys = mutableMapOf<String, SecretKey>()

    override fun capabilities() = ChipCaps(screenLock = true, biometric = true, hardware = true)

    override fun create(name: String, unlock: ChipUnlock): ChipSecurity {
        keys[name] = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        return ChipSecurity.PROTECTED
    }

    override fun seal(name: String, plain: ByteArray, aad: ByteArray, prompt: ChipPrompt): ByteArray {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, keys.getValue(name), GCMParameterSpec(128, iv))
        c.updateAAD(aad)
        return iv + c.doFinal(plain)
    }

    override fun open(name: String, sealed: ByteArray, aad: ByteArray, prompt: ChipPrompt): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, keys.getValue(name), GCMParameterSpec(128, sealed, 0, 12))
        c.updateAAD(aad)
        return c.doFinal(sealed, 12, sealed.size - 12)
    }

    override fun delete(name: String) {
        keys.remove(name)
    }

    override fun problem(): String? = null
}

/**
 * Signing in person on two phones side by side, the real flow: the core (built for this
 * machine), its encrypted session over TCP on 127.0.0.1, and the fake NCA servers
 * (crates/kzsigner/examples/fake_nca.rs, started by scripts/screenshots.sh). Saves one PNG per
 * step into -Pkzsigner.screenshots.
 */
@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w860dp-h900dp-xhdpi")
class InPersonScreenshots {
    @get:Rule
    val compose = createComposeRule()

    private val out = File(System.getProperty("kzsigner.screenshots")!!).also { it.mkdirs() }
    private val testdata = File(System.getProperty("kzsigner.testdata")!!)
    private val cas = File(testdata, "../apps/android/compose/src/uitest/assets/testca").listFiles()!!.map { it.readBytes() }
    private val nca = Nca.forTests("http://127.0.0.1:18080/", "http://127.0.0.1:18081/", cas)

    /** A phone with one key, added from testdata/inperson. */
    private fun phone(name: String): Pair<Vault, KeyInfo> {
        val dir = File(System.getProperty("java.io.tmpdir"), "kzsigner-shots-$name-${System.nanoTime()}").also { it.mkdirs() }
        val v = Vault(File(dir, "keys.kzs").path, SoftChip())
        v.addKey(nca, File(testdata, "inperson/$name.p12").readBytes(), "", ChipPrompt("", "", ""))
        return v to v.keys().keys.first()
    }

    @Composable
    private fun Phone(label: String, content: @Composable () -> Unit) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(
                label,
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFF5A6270),
                modifier = Modifier.padding(bottom = 8.dp)
            )
            Box(
                Modifier.size(390.dp, 820.dp)
                    .clip(RoundedCornerShape(28.dp))
                    .border(2.dp, Color(0xFFCDD2DA), RoundedCornerShape(28.dp))
            ) { content() }
        }
    }

    private fun shot(name: String) {
        compose.waitForIdle()
        val b = compose.onRoot().captureToImage().asAndroidBitmap()
        File(out, "$name.png").outputStream().use { b.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    /** Runs the main thread (where the flows post their state) until [what], 30 s at most. */
    private fun waitFor(what: () -> Boolean) {
        val end = System.currentTimeMillis() + 30_000
        while (true) {
            shadowOf(Looper.getMainLooper()).idle()
            compose.waitForIdle()
            if (what()) return
            if (System.currentTimeMillis() > end) {
                shot("failed")
                throw AssertionError("timed out")
            }
            Thread.sleep(50)
        }
    }

    @Test
    fun twoPhones() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        val (lv, lk) = phone("lawyer")
        val (sv, sk) = phone("signer")
        val here = { listOf("127.0.0.1") }
        val lawyer = InPersonFlow(scope, Dispatchers.IO, Dispatchers.Main, { lv }, { nca }, here)
        val signer = InPersonFlow(scope, Dispatchers.IO, Dispatchers.Main, { sv }, { nca }, here)
        lawyer.paper = Paper("Lease-agreement.pdf", File(testdata, "pdf/plain.pdf").readBytes())
        // the camera, played by handing over the code the lawyer's phone shows
        val camera: () -> Unit = { signer.scanned = lawyer.qr }

        compose.setContent {
            KzsignerTheme {
                Row(
                    Modifier.fillMaxSize().background(Color(0xFFF3F5F8)).padding(20.dp),
                    horizontalArrangement = Arrangement.spacedBy(20.dp)
                ) {
                    Phone("Lawyer's phone") { MeetScreen(lk, { true }, lawyer, {}, {}) }
                    Phone("Signer's phone") { VisitScreen(sk, { true }, signer, {}, {}, camera) }
                }
            }
        }
        shot("1-lawyer-starts")

        // 1. the lawyer signs first and shows the QR code
        compose.onNodeWithText("Sign and show the QR code").performClick()
        waitFor { lawyer.qr != null }
        shot("2-qr-shown")

        // 2. the signer scans it and reads the request
        compose.onNodeWithText("Open the camera").performClick()
        waitFor { signer.visit is Visit.Sign && signer.reading != null && lawyer.desk is Desking.Here }
        shot("3-signer-reads")

        // 3. the signer signs; the lawyer gets the signature to accept
        compose.onNodeWithText("Sign").performClick()
        waitFor { lawyer.desk is Desking.Deciding }
        shot("4-lawyer-accepts")

        // 4. accepted: the signer is told, the lawyer's phone shows the next QR code
        val first = lawyer.qr
        compose.onNodeWithText("Accept").performClick()
        waitFor { signer.outcome != null && lawyer.qr != first }
        shot("5-next-qr")

        // 5. everyone signed: the final QR code hands the signed PDF to each signer
        compose.onNodeWithText("Everyone signed: finish").performClick()
        waitFor { lawyer.finished != null }
        compose.onNodeWithText("Scan again").performClick()
        waitFor { (signer.visit as? Visit.Signed)?.document != null }
        shot("6-final-copy")

        runBlocking {
            lawyer.close()
            signer.leave()
        }
    }
}
