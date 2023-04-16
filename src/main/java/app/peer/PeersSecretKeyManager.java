package app.peer;

import javax.crypto.SecretKey;
import java.util.Map;

public class PeersSecretKeyManager {
    private static Map<String, SecretKey> peersSecretKeyManager;

    public static SecretKey getPeerSecretKey(String peerId) {
        return peersSecretKeyManager.getOrDefault(peerId, null);
    }

    public static void setPeersSecretKey(String peerId, SecretKey peerKey) {
        peersSecretKeyManager.put(peerId, peerKey);
    }
}
