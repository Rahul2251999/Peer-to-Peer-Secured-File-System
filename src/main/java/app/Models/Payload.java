package app.Models;

import java.io.Serializable;

public class Payload implements Serializable {
    private final String command;
    private final PeerInfo peerInfo;

    private Payload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
    }

    public String getCommand() {
        return command;
    }

    public PeerInfo getPeerInfo() {
        return peerInfo;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Payload build() {
            return new Payload(this);
        }
    }
}
