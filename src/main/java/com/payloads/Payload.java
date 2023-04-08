package com.payloads;

import java.io.Serializable;

public class Payload implements Serializable {
    private final String command;
    private final String peer_id;

    private Payload(Builder builder) {
        this.command = builder.command;
        this.peer_id = builder.peer_id;
    }

    public String getCommand() {
        return command;
    }

    public String getPeerId() {
        return peer_id;
    }

    public static class Builder {
        private String command;
        private String peer_id;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerId(String peer_id) {
            this.peer_id = peer_id;
            return this;
        }

        public Payload build() {
            return new Payload(this);
        }
    }
}
