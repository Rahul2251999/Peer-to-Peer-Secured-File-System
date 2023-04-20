package app.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;

public class AES {
    private static final String ALGORITHM = "AES";
    public static byte[] encrypt(SecretKey secretKey, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = new byte[cipher.getBlockSize()];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] ciphertext = cipher.doFinal(plaintext);

        return concatenate(ivBytes, ciphertext);
    }

    public static byte[] decrypt(SecretKey secretKey, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] ivBytes = Arrays.copyOfRange(ciphertext, 0, cipher.getBlockSize());
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        byte[] ciphertextWithoutIv = Arrays.copyOfRange(ciphertext, cipher.getBlockSize(), ciphertext.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        return cipher.doFinal(ciphertextWithoutIv);
    }

    private static byte[] concatenate(byte[] a, byte[] b) {
        int aLen = a.length;
        int bLen = b.length;
        byte[] c = new byte[aLen + bLen];
        System.arraycopy(a, 0, c, 0, aLen);
        System.arraycopy(b, 0, c, aLen, bLen);
        return c;
    }

    public static void writeKeyToFile(SecretKey key, String filePath) throws IOException {
        Path path = Paths.get(filePath);
        byte[] encodedKey = key.getEncoded();

        // Create the file if it does not exist
        if (!Files.exists(path)) {
            System.out.println("HI");
            Files.createFile(path);
        }

        Files.write(path, encodedKey);
    }

    public static SecretKey getSecretKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }
}
