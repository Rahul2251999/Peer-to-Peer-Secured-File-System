package app.Models.Payloads;

import java.io.Serializable;

public class FetchKeyPayload extends ResponsePayload implements Serializable {
    private final byte[] key;

    public FetchKeyPayload(Builder builder) {
        super();
        this.statusCode = builder.statusCode;
        this.message = builder.message;
        this.key = builder.key;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private byte[] key;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setKey(byte[] key) {
            this.key = key;
            return this;
        }

        public FetchKeyPayload build() {
            return new FetchKeyPayload(this);
        }
    }
}
