package app.Models.Payloads.Peer;

import app.Models.Payloads.CreateFileResponsePayload;
import app.Models.Payloads.ResponsePayload;

import java.io.Serializable;
import java.util.Map;

public class ReadFileResponsePayload extends ResponsePayload implements Serializable {
    private String fileContent;

    private ReadFileResponsePayload(Builder builder) {
        this.statusCode = builder.statusCode;
        this.message = builder.message;
        this.fileContent = builder.fileContent;
    }

    public String readFileContent() {
        return this.fileContent;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private String fileContent;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setFileContent(String fileContent) {
            this.fileContent = fileContent;
            return this;
        }

        public ReadFileResponsePayload build() {
            return new ReadFileResponsePayload(this);
        }
    }
}
