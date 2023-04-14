package app.Models;

import javax.crypto.SecretKey;

public class PeerDB extends PeerInfo {
    private boolean isActive;
    private SecretKey key;

    public PeerDB(PeerInfo peerInfo, boolean isActive, SecretKey key) {
        super(peerInfo.getPeer_id(), peerInfo.getPort_no());
        this.isActive = isActive;
        this.key = key;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public SecretKey getKey() {
        return key;
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }
}
