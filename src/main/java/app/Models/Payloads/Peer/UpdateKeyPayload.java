package app.Models.Payloads.Peer;

import app.Models.Payloads.Payload;
import app.Models.PeerInfo;

import java.io.Serializable;

public class UpdateKeyPayload extends Payload implements Serializable {
    private final byte[] key;

    public UpdateKeyPayload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.key = builder.key;
    }

    public byte[] getKey() {
        return key;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;
        private byte[] key;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setKey(byte[] key) {
            this.key = key;
            return this;
        }

        public UpdateKeyPayload build() {
            return new UpdateKeyPayload(this);
        }
    }
}
