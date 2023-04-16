package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;

public class EncryptedPayload extends Payload implements Serializable {
    private byte[] data;

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public void setPeerInfo(PeerInfo peerInfo) {
        this.peerInfo = peerInfo;
    }

    public PeerInfo getPeerInfo() {
        return this.peerInfo;
    }
}
