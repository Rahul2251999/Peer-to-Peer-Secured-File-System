package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;

public class RestoreFilePayload extends Payload implements Serializable {
    private String parent;
    private String fileName;

    public RestoreFilePayload(Builder builder) {
        super();
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.fileName = builder.fileName;
        this.parent = builder.parent;
    }

    public String getParent() {
        return parent;
    }

    public String getFileName() {
        return fileName;
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

        public RestoreFilePayload build() {
            return new RestoreFilePayload(this);
        }
    }
}
