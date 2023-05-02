package app.Models.Payloads;

import app.Models.PeerInfo;

import java.io.Serializable;
import java.util.Set;

public class FileListingResponsePayload extends ResponsePayload implements Serializable {
    private Set<String> untraceableFiles;

    public FileListingResponsePayload(Builder builder) {
        this.statusCode = builder.statusCode;
        this.message = builder.message;
        this.untraceableFiles = builder.untraceableFiles;
    }

    public Set<String> getUnTraceableFiles() {
        return untraceableFiles;
    }

    public static class Builder {
        private int statusCode;
        private String message;
        private Set<String> untraceableFiles;

        public Builder setMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder setStatusCode(int statusCode) {
            this.statusCode = statusCode;
            return this;
        }

        public Builder setUnTraceableFiles(Set<String> untraceableFiles) {
            this.untraceableFiles = untraceableFiles;
            return this;
        }

        public FileListingResponsePayload build() {
            return new FileListingResponsePayload(this);
        }
    }
}
