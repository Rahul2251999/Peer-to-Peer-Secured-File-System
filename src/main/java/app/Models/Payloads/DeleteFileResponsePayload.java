package app.Models.Payloads;

import java.io.Serializable;
import java.util.Map;

public class DeleteFileResponsePayload extends ResponsePayload implements Serializable {
    private Map<String, Integer> toBeDeletedPeers;

    public DeleteFileResponsePayload(Builder builder) {
        this.toBeDeletedPeers = builder.toBeDeletedPeers;
        this.message = builder.message;
        this.statusCode = builder.statusCode;
    }

    public Map<String, Integer> getToBeDeletedPeers() {
        return toBeDeletedPeers;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private Map<String, Integer> toBeDeletedPeers;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setToBeDeletedPeers(Map<String, Integer> toBeReplicatedPeers) {
            this.toBeDeletedPeers = toBeReplicatedPeers;
            return this;
        }

        public DeleteFileResponsePayload build() {
            return new DeleteFileResponsePayload(this);
        }
    }
}
