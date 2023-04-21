package app.Models.Payloads.Peer;

import app.Models.Payloads.Payload;
import app.Models.PeerInfo;

import java.io.Serializable;

public class UpdateFilePayload extends Payload implements Serializable {
    private String fileName;
    private String fileContents;

    public UpdateFilePayload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.fileName = builder.fileName;
        this.fileContents = builder.fileContents;
    }

    public String getFileName() {
        return fileName;
    }

    public String getFileContents() {
        return fileContents;
    }

    public static class Builder {
        private String fileName;
        private String fileContents;
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

        public Builder setFileName(String fileName) {
            this.fileName = fileName;
            return this;
        }

        public Builder setFileContents(String fileContents) {
            this.fileContents = fileContents;
            return this;
        }

        public UpdateFilePayload build() {
            return new UpdateFilePayload(this);
        }
    }
}
