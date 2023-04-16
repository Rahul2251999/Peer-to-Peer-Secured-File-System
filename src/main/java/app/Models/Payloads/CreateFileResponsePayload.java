package app.Models.Payloads;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class CreateFileResponsePayload extends ResponsePayload implements Serializable {
    private Map<String, Integer> replicatedPeerPorts = null;

    private CreateFileResponsePayload(Builder builder) {
        this.statusCode = builder.statusCode;
        this.message = builder.message;
        this.replicatedPeerPorts = builder.replicatedPeerPorts;
    }

    public Map<String, Integer> getReplicatedPeerPorts() {
        return replicatedPeerPorts;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private Map<String, Integer> replicatedPeerPorts;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setReplicatedPeerPorts(Map<String, Integer> replicatedPeerPorts) {
            this.replicatedPeerPorts = replicatedPeerPorts;
            return this;
        }

        public CreateFileResponsePayload build() {
            return new CreateFileResponsePayload(this);
        }
    }
}
