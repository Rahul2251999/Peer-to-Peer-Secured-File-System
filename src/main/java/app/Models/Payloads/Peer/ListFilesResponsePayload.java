package app.Models.Payloads.Peer;

import app.Models.Payloads.ResponsePayload;

import java.io.Serializable;
import java.util.List;

public class ListFilesResponsePayload extends ResponsePayload implements Serializable {
    private List<String> lines;

    public ListFilesResponsePayload(Builder builder) {
        this.message = builder.message;
        this.statusCode = builder.statusCode;
        this.lines = builder.lines;
    }

    public List<String> getLines() {
        return lines;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private List<String> lines;

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setLines(List<String> lines) {
            this.lines = lines;
            return this;
        }

        public ListFilesResponsePayload build() {
            return new ListFilesResponsePayload(this);
        }
    }
}
