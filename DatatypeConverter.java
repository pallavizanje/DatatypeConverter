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

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITER = 100_000;
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int AES_KEY_BITS = 256;       // fallback to 128 if needed
    private static final int GCM_TAG_BITS = 128;

    private CryptoUtil() {}

    public static String encrypt(String plaintext, String password) throws GeneralSecurityException {
        if (plaintext == null || password == null) {
            throw new IllegalArgumentException("Null values are not allowed.");
        }

        byte[] salt = new byte[SALT_LEN];
        SECURE_RANDOM.nextBytes(salt);

        SecretKey aesKey = deriveKey(password, salt, AES_KEY_BITS);

        byte[] iv = new byte[IV_LEN];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            out.write(salt);
            out.write(iv);
            out.write(ciphertext);
            return Base64.getEncoder().encodeToString(out.toByteArray());
        }
    }

    public static String decrypt(String base64Cipher, String password) throws GeneralSecurityException {
        if (base64Cipher == null || password == null) {
            throw new IllegalArgumentException("Null values are not allowed.");
        }

        byte[] all = Base64.getDecoder().decode(base64Cipher);

        if (all.length < SALT_LEN + IV_LEN + 1) {
            throw new IllegalArgumentException("Ciphertext too short");
        }

        byte[] salt = Arrays.copyOfRange(all, 0, SALT_LEN);
        byte[] iv = Arrays.copyOfRange(all, SALT_LEN, SALT_LEN + IV_LEN);
        byte[] ciphertext = Arrays.copyOfRange(all, SALT_LEN + IV_LEN, all.length);

        SecretKey aesKey = deriveKey(password, salt, AES_KEY_BITS);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

        byte[] plain = cipher.doFinal(ciphertext);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static SecretKey deriveKey(String password, byte[] salt, int keyBits)
            throws GeneralSecurityException {

        KeySpec spec = new PBEKeySpec(
                password.toCharArray(),
                salt,
                PBKDF2_ITER,
                keyBits
        );

        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGO);
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
    }
}
