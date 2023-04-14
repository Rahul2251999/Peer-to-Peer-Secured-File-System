package app.Models.Payloads;

import java.io.Serializable;

public class ResponsePayload implements Serializable {
    protected int statusCode;
    protected String message;

    public ResponsePayload() {}

    private ResponsePayload(Builder builder) {
        this.statusCode = builder.statusCode;
        this.message = builder.message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getMessage() {
        return message;
    }

    public static class Builder {
        private int statusCode;
        private String message;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public ResponsePayload build() {
            return new ResponsePayload(this);
        }
    }
}
