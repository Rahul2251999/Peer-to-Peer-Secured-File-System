package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.*;

public class Payload implements Serializable {
    protected String command;
    protected PeerInfo peerInfo;

    protected Payload() {}

    protected Payload(Builder builder) {
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
