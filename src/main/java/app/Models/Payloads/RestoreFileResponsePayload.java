package app.Models.Payloads;

import java.io.Serializable;
import java.util.Map;

public class RestoreFileResponsePayload extends ResponsePayload implements Serializable {
    private Map<String, Integer> toBeReplicatedPeers;

    public RestoreFileResponsePayload(Builder builder) {
        super();
        this.message = builder.message;
        this.statusCode = builder.statusCode;
        this.toBeReplicatedPeers = builder.toBeReplicatedPeers;
    }

    public Map<String, Integer> getToBeReplicatedPeers() {
        return toBeReplicatedPeers;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private Map<String, Integer> toBeReplicatedPeers;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setToBeReplicatedPeers(Map<String, Integer> toBeReplicatedPeers) {
            this.toBeReplicatedPeers = toBeReplicatedPeers;
            return this;
        }

        public RestoreFileResponsePayload build() {
            return new RestoreFileResponsePayload(this);
        }
    }
}
