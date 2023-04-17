package app.Models.Payloads.Peer;

import app.Models.Payloads.Payload;
import app.Models.PeerInfo;

import java.io.Serializable;

public class FetchKeyPayload extends Payload implements Serializable {
    private String requestingPeerId = null;

    public FetchKeyPayload(Builder builder) {
        this.peerInfo = builder.peerInfo;
        this.command = builder.command;
        this.requestingPeerId = builder.requestingPeerId;
    }

    public String getRequestingPeerId() {
        return requestingPeerId;
    }

    public static class Builder {
        private PeerInfo peerInfo;
        private String command;
        private String requestingPeerId;

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setRequestingPeerId(String peerId) {
            this.requestingPeerId = peerId;
            return this;
        }

        public FetchKeyPayload build() {
            return new FetchKeyPayload(this);
        }
    }
}
