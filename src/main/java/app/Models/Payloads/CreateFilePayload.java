package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class CreateFilePayload extends Payload implements Serializable {
    private final String fileName;
    private final String parent;
    private final Map<String, String> accessList;

    public CreateFilePayload(Builder builder) {
        super();
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.fileName = builder.fileName;
        this.parent = builder.parent;
        this.accessList = builder.accessList;
    }

    public String getFileName() {
        return fileName;
    }

    public String getParent() { return parent; }

    public Map<String, String> getAccessList() {
        return accessList;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;
        private String fileName;
        private String parent;
        private Map<String, String> accessList;

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

        public Builder setParent(String parent) {
            Path path = Paths.get(parent).normalize();
            this.parent = path.toString();
            return this;
        }

        public Builder setAccessList(Map<String, String> accessList) {
            this.accessList = accessList;
            return this;
        }

        public CreateFilePayload build() {
            return new CreateFilePayload(this);
        }
    }
}
