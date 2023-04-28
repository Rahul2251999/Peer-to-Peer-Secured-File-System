package app.constants;

import app.utils.RSA;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class KeyManager {
    private static PrivateKey privateKey;
    private static PublicKey publicKey;

    public KeyManager(String filePath) {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(filePath, "private.der"));
            privateKey = RSA.getPrivateKey(keyBytes);
            keyBytes = Files.readAllBytes(Paths.get(filePath, "public.der"));
            publicKey = RSA.getPublicKey(keyBytes);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey() {
        return privateKey;
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }
}
