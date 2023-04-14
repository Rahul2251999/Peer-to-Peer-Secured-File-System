package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;

public class InitPayload extends Payload implements Serializable {
    private final byte[] key;

    private InitPayload(Builder builder) {
        super();
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

        public InitPayload build() {
            return new InitPayload(this);
        }
    }
}
