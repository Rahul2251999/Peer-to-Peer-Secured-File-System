package app.FDS;

import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import app.Models.Payloads.InitPayload;
import app.Models.Payloads.ResponsePayload;
import app.MongoConnectionManager;
import app.constants.KeyManager;
import app.utils.RSA;
import com.mongodb.client.MongoDatabase;

import app.Models.PeerDB;
import app.Models.PeerInfo;
import app.Models.Payloads.Payload;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static app.constants.Constants.TerminalColors.*;

class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private ObjectInputStream clientReader;
    private ObjectOutputStream clientWriter;
    private PeerInfo peerInfo;
    private static Map<String, PeerDB> peerDBMap = new HashMap<>();

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try {
            System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + "\n" + ANSI_RESET);

            clientReader = new ObjectInputStream(clientSocket.getInputStream());
            clientWriter = new ObjectOutputStream(clientSocket.getOutputStream());

            Payload clientInput;
            while ((clientInput = (Payload) clientReader.readObject()) != null) {
                PeerInfo peerInfo = clientInput.getPeerInfo();
                this.peerInfo = peerInfo;

                ResponsePayload response = processInput(clientInput);
                clientWriter.writeObject(response);
                clientWriter.flush();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "Error: " + e.getMessage() + ANSI_RESET);
            PeerDB peerDBItem = peerDBMap.get(this.peerInfo.getPeer_id());
            peerDBItem.setActive(false);
            peerDBMap.put(this.peerInfo.getPeer_id(), peerDBItem);
        } catch (ClassNotFoundException e) {
            System.out.println(ANSI_RED + "ClassNotFoundException: " + e.getMessage() + ANSI_RESET);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
                if (clientReader != null) {
                    clientReader.close();
                }
                if (clientWriter != null) {
                    clientWriter.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "Error closing client socket: " + e.getMessage() + ANSI_RESET);
            }
        }
    }

    private ResponsePayload processInput(Payload clientPayload) throws Exception {
        PeerInfo peerInfo = clientPayload.getPeerInfo();
        String peer_id = peerInfo.getPeer_id();
        System.out.println(ANSI_BLUE + "Serving Peer: " + peer_id);
        System.out.println("Executing: " + clientPayload.getCommand() + ANSI_RESET);

        ResponsePayload responsePayload = null;

        String[] command = clientPayload.getCommand().split(" ", 2);
        String commandName = command[0];
        switch (commandName) {
            case "registerPeer":
                InitPayload initPayload = (InitPayload) clientPayload;
                byte[] keyBytes = RSA.decrypt(initPayload.getKey(), KeyManager.getPrivateKey());
                SecretKey key = new SecretKeySpec(keyBytes, "AES");

                PeerDB peerDBItem = new PeerDB(peerInfo, true, key);
                peerDBMap.put(peer_id, peerDBItem);

                String response = "Peer registered Successfully";
                responsePayload = new ResponsePayload.Builder()
                        .setStatusCode(200)
                        .setMessage(response)
                        .build();
                break;
            default:
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + command + ANSI_RESET);
        }

        return responsePayload;
    }
}