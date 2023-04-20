package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;
import java.nio.file.Path;
import java.nio.file.Paths;

public class ChangeDirectoryPayload extends Payload implements Serializable {
    private final String pwd;
    private final String changeInto;

    public ChangeDirectoryPayload(Builder builder) {
        super();
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
        this.pwd = builder.pwd;
        this.changeInto = builder.changeInto;
    }

    public String getPwd() {
        return pwd;
    }

    public String getChangeInto() { return changeInto; }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;
        private String pwd;
        private String changeInto;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setPwd(String pwd) {
            Path path = Paths.get(pwd).normalize();
            this.pwd = path.toString();
            return this;
        }

        public Builder setChangeInto(String changeInto) {
            Path path = Paths.get(changeInto).normalize();
            this.changeInto = path.toString();
            return this;
        }

        public ChangeDirectoryPayload build() {
            return new ChangeDirectoryPayload(this);
        }
    }
}
