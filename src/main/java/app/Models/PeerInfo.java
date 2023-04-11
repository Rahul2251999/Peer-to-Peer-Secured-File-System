package app.Models;

import java.io.Serializable;

public class PeerInfo implements Serializable {
    private String peer_id = null;
    private int port_no;

    public PeerInfo(String peer_id, int port_no) {
        this.peer_id = peer_id;
        this.port_no = port_no;
    }

    public int getPort_no() {
        return port_no;
    }

    public String getPeer_id() {
        return peer_id;
    }
}
