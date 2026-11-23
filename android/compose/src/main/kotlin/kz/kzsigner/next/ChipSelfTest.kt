package kz.kzsigner.next

import android.os.Build
import android.util.Log
import kz.kzsigner.core.ChipException
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.ChipUnlock

/**
 * CI's check of [KeystoreChip] on an emulator (android/uitest, ComposeApp): started with
 * `--ez chiptest true`, it makes a key for each way of unlocking, seals and opens with it
 * (the prompt answered by the virtual fingerprint sensor), and checks a changed box does not
 * open. Logs each step under KZSELFTEST, ending in CHIP PASS or CHIP FAIL. Emulators only:
 * emulators keep keys in software, where the app itself uses the key's password instead, so
 * this is the only place the prompt path runs there.
 */
object ChipSelfTest {
    private const val TAG = "KZSELFTEST"

    fun emulator(): Boolean = Build.HARDWARE == "ranchu" || Build.HARDWARE == "goldfish"

    fun run(chip: KeystoreChip) {
        Thread {
            try {
                val caps = chip.capabilities()
                Log.i(TAG, "CHIP caps $caps")
                if (!caps.screenLock) throw Exception("no screen lock seen")
                val ways = buildList {
                    add(ChipUnlock.NONE)
                    add(ChipUnlock.BIOMETRIC_OR_PIN)
                    if (caps.biometric) add(ChipUnlock.BIOMETRIC_ONLY)
                }
                val plain = "kzsigner chip test".toByteArray()
                val aad = byteArrayOf(7, 8, 9)
                for (way in ways) {
                    val name = "kzsigner-chiptest-$way"
                    val prompt = ChipPrompt("kzsigner chip test", way.toString(), "")
                    val where = chip.create(name, way)
                    Log.i(TAG, "CHIP create $way $where")
                    val sealed = chip.seal(name, plain, aad, prompt)
                    Log.i(TAG, "CHIP seal $way ok")
                    if (!chip.open(name, sealed, aad, prompt).contentEquals(plain)) {
                        throw Exception("open gave other bytes")
                    }
                    Log.i(TAG, "CHIP open $way ok")
                    val bad = sealed.clone()
                    bad[bad.size - 1] = (bad[bad.size - 1].toInt() xor 1).toByte()
                    try {
                        chip.open(name, bad, aad, prompt)
                        throw Exception("a changed box opened")
                    } catch (e: ChipException.Failed) {
                        Log.i(TAG, "CHIP changed box refused")
                    }
                    chip.delete(name)
                }
                Log.i(TAG, "CHIP PASS")
            } catch (e: Exception) {
                Log.e(TAG, "CHIP FAIL $e")
            }
        }.start()
    }
}
