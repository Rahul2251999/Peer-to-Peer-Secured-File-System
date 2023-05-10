package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;
import java.util.Set;

public class FileListingPayload extends Payload implements Serializable {
    private Set<String> files;

    public FileListingPayload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.files = builder.files;
    }

    public Set<String> getFiles() {
        return files;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;
        private Set<String> files;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setFiles(Set<String> files) {
            this.files = files;
            return this;
        }

        public FileListingPayload build() {
            return new FileListingPayload(this);
        }
    }
}
