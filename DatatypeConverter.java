import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class CryptoUtil {
    private CryptoUtil() {}

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 100_000;
    private static final int SALT_LEN = 16;          // bytes
    private static final int IV_LEN = 12;            // bytes for GCM
    private static final int AES_KEY_BITS = 256;     // fallback to 128 if 256 is unavailable
    private static final int GCM_TAG_BITS = 128;

    public static String encrypt(String plaintext, char[] password) throws GeneralSecurityException {
        if (plaintext == null || password == null) throw new IllegalArgumentException("Null input");

        byte[] salt = new byte[SALT_LEN];
        SECURE_RANDOM.nextBytes(salt);

        SecretKey aesKey = deriveKey(password, salt, AES_KEY_BITS);

        byte[] iv = new byte[IV_LEN];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // output = salt || iv || ciphertext (ciphertext includes GCM tag)
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            out.write(salt);
            out.write(iv);
            out.write(ciphertext);
            return Base64.getEncoder().encodeToString(out.toByteArray());
        } finally {
            // try to clear sensitive data
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
        }
    }

    public static String decrypt(String base64Input, char[] password) throws GeneralSecurityException {
        if (base64Input == null || password == null) throw new IllegalArgumentException("Null input");

        byte[] all = Base64.getDecoder().decode(base64Input);

        if (all.length < SALT_LEN + IV_LEN + 1) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        byte[] salt = Arrays.copyOfRange(all, 0, SALT_LEN);
        byte[] iv = Arrays.copyOfRange(all, SALT_LEN, SALT_LEN + IV_LEN);
        byte[] ciphertext = Arrays.copyOfRange(all, SALT_LEN + IV_LEN, all.length);

        SecretKey aesKey = deriveKey(password, salt, AES_KEY_BITS);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        try {
            byte[] plain = cipher.doFinal(ciphertext);
            return new String(plain, StandardCharsets.UTF_8);
        } finally {
            // clear sensitive arrays
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt, int keyBits) throws GeneralSecurityException {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, keyBits);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(KDF_ALGO);
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            SecretKey key = new SecretKeySpec(keyBytes, "AES");

            // clear keyBytes if possible
            Arrays.fill(keyBytes, (byte) 0);
            return key;
        } finally {
            // Do NOT clear the password here — caller owns the char[] and should clear it when appropriate.
        }
    }
}
