package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;

public class FileReplicateRequestPayload extends Payload implements Serializable {
    private String fileName;
    private PeerInfo toBeReplicatedPeer;

    public FileReplicateRequestPayload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.fileName = builder.fileName;
        this.toBeReplicatedPeer = builder.toBeReplicatedPeer;
    }

    public String getFileName() {
        return fileName;
    }

    public PeerInfo getToBeReplicatedPeer() {
        return toBeReplicatedPeer;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;
        private String fileName;
        private PeerInfo toBeReplicatedPeer;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setFileName(String fileName) {
            this.fileName = fileName;
            return this;
        }

        public Builder setToBeReplicatedPeer(PeerInfo toBeReplicatedPeer) {
            this.toBeReplicatedPeer = toBeReplicatedPeer;
            return this;
        }

        public FileReplicateRequestPayload build() {
            return new FileReplicateRequestPayload(this);
        }
    }
}
