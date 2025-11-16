import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtil.class);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITER = 100_000;
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;

    private CryptoUtil() {}

    // --------------------------
    // ENCRYPT
    // --------------------------
    public static String encrypt(String plaintext, String password) throws GeneralSecurityException {
        LOGGER.info("Starting encryption process...");
        LOGGER.debug("Input plaintext: {}", plaintext);

        byte[] salt = new byte[SALT_LEN];
        SECURE_RANDOM.nextBytes(salt);
        LOGGER.debug("Generated salt (Base64): {}", Base64.getEncoder().encodeToString(salt));

        SecretKey aesKey = deriveKey(password, salt, AES_KEY_BITS);
        LOGGER.info("Key derivation completed.");

        byte[] iv = new byte[IV_LEN];
        SECURE_RANDOM.nextBytes(iv);
        LOGGER.debug("Generated IV (Base64): {}", Base64.getEncoder().encodeToString(iv));

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        LOGGER.info("Cipher initialized for ENCRYPT.");

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        LOGGER.debug("Encrypted ciphertext (Base64): {}", Base64.getEncoder().encodeToString(ciphertext));

        String finalCipher = buildFinalOutput(salt, iv, ciphertext);
        LOGGER.info("Encryption finished successfully.");

        return finalCipher;
    }

    // --------------------------
    // DECRYPT
    // --------------------------
    public static String decrypt(String base64Cipher, String password) throws GeneralSecurityException {
        LOGGER.info("Starting decryption process...");
        LOGGER.debug("Provided cipher text: {}", base64Cipher);

        byte[] all = Base64.getDecoder().decode(base64Cipher);
        LOGGER.debug("Decoded complete byte array length: {}", all.length);

        byte[] salt = Arrays.copyOfRange(all, 0, SALT_LEN);
        byte[] iv = Arrays.copyOfRange(all, SALT_LEN, SALT_LEN + IV_LEN);
        byte[] ciphertext = Arrays.copyOfRange(all, SALT_LEN + IV_LEN, all.length);

        LOGGER.debug("Extracted salt (Base64): {}", Base64.getEncoder().encodeToString(salt));
        LOGGER.debug("Extracted IV (Base64): {}", Base64.getEncoder().encodeToString(iv));
        LOGGER.debug("Extracted ciphertext (Base64): {}", Base64.getEncoder().encodeToString(ciphertext));

        SecretKey aesKey = deriveKey(password, salt, AES_KEY_BITS);
        LOGGER.info("Key derivation for decrypt completed.");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
        LOGGER.info("Cipher initialized for DECRYPT.");

        byte[] plainBytes = cipher.doFinal(ciphertext);
        String plain = new String(plainBytes, StandardCharsets.UTF_8);

        LOGGER.info("Decryption finished successfully.");
        LOGGER.debug("Decrypted plaintext: {}", plain);

        return plain;
    }


    // --------------------------
    // KEY DERIVATION
    // --------------------------
    private static SecretKey deriveKey(String password, byte[] salt, int keyBits)
            throws GeneralSecurityException {

        LOGGER.info("Deriving key using PBKDF2WithHmacSHA256...");
        LOGGER.debug("Password length: {}", password.length());
        LOGGER.debug("Salt length: {}", salt.length);
        LOGGER.debug("Iterations: {}", PBKDF2_ITER);
        LOGGER.debug("Key size: {} bits", keyBits);

        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITER, keyBits);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGO);

        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        LOGGER.debug("Raw AES key generated (not printing for security reasons)");

        return new SecretKeySpec(keyBytes, "AES");
    }

    // --------------------------
    // BUILD OUTPUT
    // --------------------------
    private static String buildFinalOutput(byte[] salt, byte[] iv, byte[] ciphertext) {
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            out.write(salt);
            out.write(iv);
            out.write(ciphertext);

            String output = Base64.getEncoder().encodeToString(out.toByteArray());
            LOGGER.debug("Final encrypted output (Base64): {}", output);

            return output;
        } catch (Exception e) {
            LOGGER.error("Error building final cipher output", e);
            throw new RuntimeException(e);
        }
    }
}
