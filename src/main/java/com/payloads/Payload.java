package com.payloads;

import java.io.Serializable;

public class Payload implements Serializable {
    private final String command;
    private final String peer_id;
    private final int port_no;

    private Payload(Builder builder) {
        this.command = builder.command;
        this.peer_id = builder.peer_id;
        this.port_no = builder.port_no;
    }

    public String getCommand() {
        return command;
    }

    public String getPeerId() {
        return peer_id;
    }

    public int getPortNo() {
        return port_no;
    }

    public static class Builder {
        private String command;
        private String peer_id;
        private int port_no;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerId(String peer_id) {
            this.peer_id = peer_id;
            return this;
        }

        public Builder setPortNo(int port_no) {
            this.port_no = port_no;
            return this;
        }

        public Payload build() {
            return new Payload(this);
        }
    }
}
