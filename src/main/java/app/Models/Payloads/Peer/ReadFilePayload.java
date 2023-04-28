package app.Models.Payloads.Peer;

import app.Models.Payloads.Payload;
import app.Models.PeerInfo;

import java.io.Serializable;

public class ReadFilePayload extends Payload implements Serializable {
    private String fileName;

    public ReadFilePayload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.fileName = builder.fileName;
    }

    public String getFileName() {
        return fileName;
    }

    public static class Builder {
        private PeerInfo peerInfo;
        private String command;
        private String fileName;

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setFileName(String fileName) {
            this.fileName = fileName;
            return this;
        }

        public ReadFilePayload build() {
            return new ReadFilePayload(this);
        }
    }
}
