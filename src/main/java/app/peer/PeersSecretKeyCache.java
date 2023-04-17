package app.peer;

import javax.crypto.SecretKey;
import java.util.HashMap;
import java.util.Map;

public class PeersSecretKeyCache {
    private static Map<String, SecretKey> peersSecretKeyManager = new HashMap<>();

    public static SecretKey getPeerSecretKey(String peerId) {
        return peersSecretKeyManager.getOrDefault(peerId, null);
    }

    public static void setPeersSecretKey(String peerId, SecretKey peerKey) {
        peersSecretKeyManager.put(peerId, peerKey);
    }
}
