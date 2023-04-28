package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;

public class DeleteFilePayload extends Payload implements Serializable {
    private String parent;
    private String fileName;

    public DeleteFilePayload(Builder builder) {
        super();
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.parent = builder.parent;
        this.fileName = builder.fileName;
    }

    public String getFileName() {
        return fileName;
    }

    public String getParent() {
        return parent;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;
        private String fileName;
        private String parent;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setParent(String parent) {
            this.parent = parent;
            return this;
        }

        public Builder setFileName(String fileName) {
            this.fileName = fileName;
            return this;
        }

        public DeleteFilePayload build() {
            return new DeleteFilePayload(this);
        }
    }
}
