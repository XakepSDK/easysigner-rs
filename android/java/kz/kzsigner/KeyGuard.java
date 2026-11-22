package kz.kzsigner;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.StrongBoxUnavailableException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;

/**
 * The phone's security chip for kzsigner's key store (src/vault.rs, src/android.rs): AES-256
 * keys in Android Keystore (StrongBox when the phone has it, else the processor's protected
 * area), AES-GCM inside it, and the system's fingerprint/PIN prompt. Keys never leave the chip.
 *
 * Every answer is a byte array whose first byte says how it went: 0 done (the rest is the
 * data), 1 cancelled, 2 the key is gone for good (reset), 3 failed (the rest is the reason).
 */
final class KeyGuard {
    private static final String STORE = "AndroidKeyStore";
    private static final byte OK = 0;
    private static final byte CANCELLED = 1;
    private static final byte RESET = 2;
    private static final byte FAILED = 3;

    /** How the owner unlocks a key; the numbers match ChipAuth in src/android.rs. */
    private static final int AUTH_NONE = 0;
    private static final int AUTH_BIOMETRIC_OR_PIN = 1;
    private static final int AUTH_BIOMETRIC = 2;

    private final Activity activity;
    /** Whether keys can live in hardware; asked once. */
    private Boolean hardware;

    KeyGuard(Activity activity) {
        this.activity = activity;
    }

    /** Runs a request from Rust; see src/android.rs (AndroidGuard). */
    byte[] call(String request, byte[] a, byte[] b) {
        String[] r = request.split("\n", -1);
        try {
            switch (r[0]) {
                case "caps":
                    return ok(caps().getBytes(StandardCharsets.UTF_8));
                case "create":
                    return ok(new byte[] {create(r[1], Integer.parseInt(r[2]))});
                case "seal":
                    return crypt(Cipher.ENCRYPT_MODE, r[1], a, b, r[2], r[3], r[4]);
                case "open":
                    return crypt(Cipher.DECRYPT_MODE, r[1], a, b, r[2], r[3], r[4]);
                case "delete":
                    keyStore().deleteEntry(r[1]);
                    return ok(new byte[0]);
                default:
                    return failed("unknown request " + r[0]);
            }
        } catch (KeyPermanentlyInvalidatedException | UnrecoverableKeyException e) {
            return new byte[] {RESET};
        } catch (Exception e) {
            return failed(e.toString());
        }
    }

    /** "screen lock,fingerprint,hardware" as 1 or 0 each. */
    private String caps() {
        KeyguardManager km = activity.getSystemService(KeyguardManager.class);
        boolean lock = km != null && km.isDeviceSecure();
        BiometricManager bm = activity.getSystemService(BiometricManager.class);
        boolean bio = bm != null
                && bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        == BiometricManager.BIOMETRIC_SUCCESS;
        return (lock ? "1" : "0") + "," + (bio ? "1" : "0") + "," + (hardware() ? "1" : "0");
    }

    /** Whether a key made here lands in hardware: tried once with a throwaway key. */
    private synchronized boolean hardware() {
        if (hardware == null) {
            String probe = "kzsigner-probe";
            try {
                hardware = create(probe, AUTH_NONE) != 3;
                keyStore().deleteEntry(probe);
            } catch (Exception e) {
                hardware = false;
            }
        }
        return hardware;
    }

    /** Makes AES key {@code name}; returns where it lives: 1 chip, 2 protected area, 3 software. */
    private byte create(String name, int auth) throws Exception {
        boolean strongBox =
                activity.getPackageManager().hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE);
        try {
            generate(name, auth, strongBox);
        } catch (StrongBoxUnavailableException e) {
            generate(name, auth, false);
        }
        SecretKey key = (SecretKey) keyStore().getKey(name, null);
        KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), STORE)
                .getKeySpec(key, KeyInfo.class);
        if (Build.VERSION.SDK_INT >= 31) {
            switch (info.getSecurityLevel()) {
                case KeyProperties.SECURITY_LEVEL_STRONGBOX:
                    return 1;
                case KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                    return 2;
                default:
                    return 3;
            }
        }
        @SuppressWarnings("deprecation")
        boolean inside = info.isInsideSecureHardware();
        return (byte) (inside ? 2 : 3);
    }

    private static void generate(String name, int auth, boolean strongBox) throws Exception {
        KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(name,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setIsStrongBoxBacked(strongBox);
        if (auth != AUTH_NONE) {
            // asked again for every use, never "unlocked for a while"
            int how = auth == AUTH_BIOMETRIC
                    ? KeyProperties.AUTH_BIOMETRIC_STRONG
                    : KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL;
            b.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, how)
                    .setUnlockedDeviceRequired(true)
                    // a fingerprint-only key dies when someone adds a fingerprint
                    .setInvalidatedByBiometricEnrollment(auth == AUTH_BIOMETRIC);
        }
        KeyGenerator g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
        g.init(b.build());
        g.generateKey();
    }

    private static KeyStore keyStore() throws Exception {
        KeyStore ks = KeyStore.getInstance(STORE);
        ks.load(null);
        return ks;
    }

    /**
     * AES-GCM with key {@code name}: encrypts (nonce chosen by the chip, put in front) or
     * decrypts. Shows the system prompt first when the key needs one, and waits for it.
     */
    private byte[] crypt(int mode, String name, byte[] data, byte[] aad, String title,
            String subtitle, String detail) throws Exception {
        SecretKey key = (SecretKey) keyStore().getKey(name, null);
        if (key == null) {
            return new byte[] {RESET};
        }
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] body = data;
        if (mode == Cipher.ENCRYPT_MODE) {
            c.init(mode, key);
        } else {
            if (data.length < 12 + 16) {
                return failed("too short");
            }
            c.init(mode, key, new GCMParameterSpec(128, data, 0, 12));
            body = Arrays.copyOfRange(data, 12, data.length);
        }
        KeyInfo info = (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), STORE)
                .getKeySpec(key, KeyInfo.class);
        if (info.isUserAuthenticationRequired()) {
            byte answer = prompt(c, info, title, subtitle, detail);
            if (answer != OK) {
                return new byte[] {answer};
            }
        }
        c.updateAAD(aad);
        byte[] out;
        try {
            out = c.doFinal(body);
        } catch (javax.crypto.AEADBadTagException e) {
            return failed("the data does not match its key");
        }
        if (mode == Cipher.ENCRYPT_MODE) {
            byte[] iv = c.getIV();
            byte[] all = new byte[iv.length + out.length];
            System.arraycopy(iv, 0, all, 0, iv.length);
            System.arraycopy(out, 0, all, iv.length, out.length);
            Arrays.fill(out, (byte) 0);
            out = all;
        }
        byte[] r = ok(out);
        Arrays.fill(out, (byte) 0);
        return r;
    }

    /** The system's fingerprint/PIN sheet for one use of {@code c}; OK, CANCELLED or FAILED. */
    private byte prompt(Cipher c, KeyInfo info, String title, String subtitle, String detail)
            throws InterruptedException {
        boolean pinToo = (info.getUserAuthenticationType() & KeyProperties.AUTH_DEVICE_CREDENTIAL) != 0;
        CountDownLatch done = new CountDownLatch(1);
        byte[] answer = {CANCELLED};
        activity.runOnUiThread(() -> {
            BiometricPrompt.Builder b = new BiometricPrompt.Builder(activity).setTitle(title);
            if (!subtitle.isEmpty()) {
                b.setSubtitle(subtitle);
            }
            if (!detail.isEmpty()) {
                b.setDescription(detail);
            }
            if (pinToo) {
                b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
            } else {
                b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);
                b.setNegativeButton(activity.getString(android.R.string.cancel),
                        activity.getMainExecutor(), (d, w) -> {});
            }
            b.setConfirmationRequired(false);
            try {
                b.build().authenticate(new BiometricPrompt.CryptoObject(c), new CancellationSignal(),
                        activity.getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                            @Override
                            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                                answer[0] = OK;
                                done.countDown();
                            }

                            @Override
                            public void onAuthenticationError(int code, CharSequence text) {
                                answer[0] = code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT
                                                || code == BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT
                                        ? FAILED
                                        : CANCELLED;
                                done.countDown();
                            }
                        });
            } catch (RuntimeException e) {
                answer[0] = FAILED;
                done.countDown();
            }
        });
        done.await();
        return answer[0];
    }

    private static byte[] ok(byte[] data) {
        byte[] r = new byte[data.length + 1];
        r[0] = OK;
        System.arraycopy(data, 0, r, 1, data.length);
        return r;
    }

    private static byte[] failed(String why) {
        byte[] m = why.getBytes(StandardCharsets.UTF_8);
        byte[] r = new byte[m.length + 1];
        r[0] = FAILED;
        System.arraycopy(m, 0, r, 1, m.length);
        return r;
    }
}
