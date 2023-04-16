package app.Models.Payloads;

import java.io.Serializable;

public class FetchKeyResponsePayload extends ResponsePayload implements Serializable {
    // key is a SecretKey instance but is
    // encrypted using CertificateAuthority PrivateKey
    private final byte[] key;

    public FetchKeyResponsePayload(Builder builder) {
        super();
        this.statusCode = builder.statusCode;
        this.message = builder.message;
        this.key = builder.key;
    }

    public byte[] getKey() {
        return key;
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

        public FetchKeyResponsePayload build() {
            return new FetchKeyResponsePayload(this);
        }
    }
}
