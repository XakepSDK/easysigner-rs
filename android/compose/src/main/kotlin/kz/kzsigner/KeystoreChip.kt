package kz.kzsigner

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.util.concurrent.CountDownLatch
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kz.kzsigner.core.Chip
import kz.kzsigner.core.ChipCaps
import kz.kzsigner.core.ChipException
import kz.kzsigner.core.ChipPrompt
import kz.kzsigner.core.ChipSecurity
import kz.kzsigner.core.ChipUnlock

/**
 * The phone's security chip for the core's key vault (ffi/src/lib.rs, `Chip`): AES-256 keys
 * in Android Keystore (StrongBox when the phone has it, else the processor's protected area),
 * AES-GCM inside it, and the system's fingerprint/PIN prompt. Keys never leave the chip.
 *
 * The same keys and layout as the earlier egui app's KeyGuard.java, so a vault written by it
 * opens here after the update: `seal` returns the 12-byte nonce chosen by the chip, then the
 * ciphertext and tag.
 *
 * The core calls it off the main thread and waits; a prompt is shown on [activity] and the
 * call returns once the owner answers it.
 */
class KeystoreChip(
    private val context: Context,
    private val activity: () -> Activity?,
) : Chip {
    /** Whether keys can live in hardware; asked once. */
    private var hardware: Boolean? = null
    private var hardwareProblem: String? = null

    override fun capabilities(): ChipCaps {
        val km = context.getSystemService(KeyguardManager::class.java)
        return ChipCaps(
            screenLock = km?.isDeviceSecure == true,
            biometric = hasFingerprint(context),
            hardware = hardware(),
        )
    }

    override fun problem(): String? = if (hardware()) null else hardwareProblem

    override fun create(name: String, unlock: ChipUnlock): ChipSecurity = guarded {
        createKey(name, unlock)
    }

    override fun seal(name: String, plain: ByteArray, aad: ByteArray, prompt: ChipPrompt): ByteArray =
        guarded { crypt(Cipher.ENCRYPT_MODE, name, plain, aad, prompt) }

    override fun open(name: String, sealed: ByteArray, aad: ByteArray, prompt: ChipPrompt): ByteArray =
        guarded { crypt(Cipher.DECRYPT_MODE, name, sealed, aad, prompt) }

    override fun delete(name: String) {
        try {
            keyStore().deleteEntry(name)
        } catch (e: Exception) {
            // nothing to delete, or the Keystore is gone: either way the key is not there
        }
    }

    /** Runs [f], turning what the Keystore throws into the core's errors. */
    private fun <T> guarded(f: () -> T): T = try {
        f()
    } catch (e: ChipException) {
        throw e
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw ChipException.KeyReset()
    } catch (e: UnrecoverableKeyException) {
        throw ChipException.KeyReset()
    } catch (e: Exception) {
        throw ChipException.Failed(why(e))
    }

    /** Whether a key made here lands in hardware: tried once with a throwaway key. */
    @Synchronized
    private fun hardware(): Boolean {
        hardware?.let { return it }
        val probe = "kzsigner-probe"
        val hw = try {
            val where = createKey(probe, ChipUnlock.NONE)
            keyStore().deleteEntry(probe)
            if (where == ChipSecurity.SOFTWARE) {
                hardwareProblem = "keys are kept in software only"
            }
            where != ChipSecurity.SOFTWARE
        } catch (e: Exception) {
            hardwareProblem = e.toString()
            false
        }
        hardware = hw
        return hw
    }

    private fun createKey(name: String, unlock: ChipUnlock): ChipSecurity {
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        var made = false
        if (strongBox) {
            try {
                generate(name, unlock, true)
                made = true
            } catch (e: Exception) {
                // StrongBox missing, busy, or without this kind of key: the protected area
                keyStore().deleteEntry(name)
            }
        }
        if (!made) {
            generate(name, unlock, false)
        }
        val info = keyInfo(keyStore().getKey(name, null) as SecretKey)
        if (Build.VERSION.SDK_INT >= 31) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> ChipSecurity.CHIP
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> ChipSecurity.PROTECTED
                else -> ChipSecurity.SOFTWARE
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) ChipSecurity.PROTECTED else ChipSecurity.SOFTWARE
    }

    private fun generate(name: String, unlock: ChipUnlock, strongBox: Boolean) {
        val b = KeyGenParameterSpec.Builder(
            name,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
        if (unlock != ChipUnlock.NONE) {
            // asked again for every use, never "unlocked for a while"
            val how = if (unlock == ChipUnlock.BIOMETRIC_ONLY) {
                KeyProperties.AUTH_BIOMETRIC_STRONG
            } else {
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            }
            b.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, how)
                .setUnlockedDeviceRequired(true)
                // a fingerprint-only key dies when someone adds a fingerprint
                .setInvalidatedByBiometricEnrollment(unlock == ChipUnlock.BIOMETRIC_ONLY)
        }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE)
        g.init(b.build())
        g.generateKey()
    }

    /**
     * AES-GCM with key [name]: encrypts (nonce chosen by the chip, put in front) or decrypts.
     * Shows the system prompt first when the key needs one, and waits for it.
     */
    private fun crypt(mode: Int, name: String, data: ByteArray, aad: ByteArray, prompt: ChipPrompt): ByteArray {
        val key = keyStore().getKey(name, null) as SecretKey? ?: throw ChipException.KeyReset()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        var body = data
        if (mode == Cipher.ENCRYPT_MODE) {
            c.init(mode, key)
        } else {
            if (data.size < 12 + 16) {
                throw ChipException.Failed("too short")
            }
            c.init(mode, key, GCMParameterSpec(128, data, 0, 12))
            body = data.copyOfRange(12, data.size)
        }
        val info = keyInfo(key)
        if (info.isUserAuthenticationRequired) {
            ask(c, info, prompt)
        }
        c.updateAAD(aad)
        val out = try {
            c.doFinal(body)
        } catch (e: AEADBadTagException) {
            throw ChipException.Failed("the data does not match its key")
        }
        if (mode == Cipher.DECRYPT_MODE) {
            return out
        }
        val iv = c.iv
        val all = iv + out
        out.fill(0)
        return all
    }

    /** The system's fingerprint/PIN sheet for one use of [c]; returns once it was passed. */
    private fun ask(c: Cipher, info: KeyInfo, prompt: ChipPrompt) {
        check(Looper.myLooper() != Looper.getMainLooper()) { "the key chip waits for the prompt: not on the main thread" }
        val a = activity() ?: throw ChipException.Failed("no window to show the prompt in")
        val pinToo = info.userAuthenticationType and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0
        val done = CountDownLatch(1)
        var answer: ChipException? = ChipException.Cancelled()
        a.runOnUiThread {
            val b = BiometricPrompt.Builder(a).setTitle(prompt.title)
            if (prompt.subtitle.isNotEmpty()) b.setSubtitle(prompt.subtitle)
            if (prompt.detail.isNotEmpty()) b.setDescription(prompt.detail)
            if (pinToo) {
                b.setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL,
                )
            } else {
                b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                b.setNegativeButton(a.getString(android.R.string.cancel), a.mainExecutor) { _, _ -> }
            }
            b.setConfirmationRequired(false)
            try {
                b.build().authenticate(
                    BiometricPrompt.CryptoObject(c),
                    CancellationSignal(),
                    a.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                            answer = null
                            done.countDown()
                        }

                        override fun onAuthenticationError(code: Int, text: CharSequence) {
                            answer = if (code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT ||
                                code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT
                            ) {
                                ChipException.Failed(text.toString())
                            } else {
                                ChipException.Cancelled()
                            }
                            done.countDown()
                        }
                    },
                )
            } catch (e: RuntimeException) {
                answer = ChipException.Failed(why(e))
                done.countDown()
            }
        }
        done.await()
        answer?.let { throw it }
    }

    private companion object {
        const val STORE = "AndroidKeyStore"

        fun keyStore(): KeyStore = KeyStore.getInstance(STORE).apply { load(null) }

        fun keyInfo(key: SecretKey): KeyInfo =
            SecretKeyFactory.getInstance(key.algorithm, STORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo

        /** An exception with its causes, which say what the Keystore refused. */
        fun why(e: Throwable): String {
            val b = StringBuilder(e.toString())
            var c = e.cause
            while (c != null && b.length < 1000) {
                b.append("; ").append(c)
                c = c.cause
            }
            return b.toString()
        }
    }
}

/** Whether a fingerprint (or face) is set up: the wording of "opens with" follows it. */
fun hasFingerprint(context: Context): Boolean = try {
    context.getSystemService(BiometricManager::class.java)
        ?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
} catch (e: RuntimeException) {
    false
}
