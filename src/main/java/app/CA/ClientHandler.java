package app.CA;

import app.Models.Payloads.FetchKeyPayload;
import app.Models.Payloads.Payload;
import app.Models.Payloads.InitPayload;
import app.Models.Payloads.ResponsePayload;
import app.Models.PeerDB;
import app.Models.PeerInfo;
import app.constants.KeyManager;
import app.utils.RSA;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import static app.constants.Constants.TerminalColors.*;

public class ClientHandler implements Runnable {
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

            Payload payload;
            while ((payload = (Payload) clientReader.readObject()) != null) {
                PeerInfo peerInfo = payload.getPeerInfo();
                this.peerInfo = peerInfo;

                ResponsePayload response = processInput(payload);
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
        }
    }

    public static ResponsePayload processInput(Payload clientPayload) throws Exception {
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

                PeerDB peerDB = new PeerDB(peerInfo, true, key);
                peerDBMap.put(peer_id, peerDB);

                String response = "Peer registered Successfully";
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(200)
                    .setMessage(response)
                    .build();
            case "registerKey":
                initPayload = (InitPayload) clientPayload;
                System.out.println(ANSI_BLUE + "Registering key for peer " + peer_id + ANSI_RESET);
                keyBytes = RSA.decrypt(initPayload.getKey(), KeyManager.getPrivateKey());
                key = new SecretKeySpec(keyBytes, "AES");
                peerDB = peerDBMap.get(peer_id);
                peerDB.setKey(key);
                peerDBMap.put(peer_id, peerDB);

                response = "Key Registered Successfully";
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(200)
                    .setMessage(response)
                    .build();
                break;
            case "fetchKey":
                // commandArgs -> peerId
                String commandArgs = command[1];
                System.out.println(ANSI_BLUE + "Fetching Key for peer " + commandArgs + ANSI_RESET);
                int statusCode = 0;
                String message = null;
                keyBytes = null;

                if (peerDBMap.containsKey(commandArgs)) {
                    peerDB = peerDBMap.get(commandArgs);
                    if (peerDB.isActive()) {
                        statusCode = 200;
                        message = "Handshake Successful!";
                        keyBytes = RSA.encrypt(peerDB.getKey().getEncoded(), KeyManager.getPrivateKey());
                    } else {
                        statusCode = 400;
                        message = "Peer inactive";
                    }
                } else {
                    statusCode = 404;
                    message = "Peer not found";
                }

                responsePayload = new FetchKeyPayload.Builder()
                    .setStatusCode(statusCode)
                    .setMessage(message)
                        .setKey(keyBytes)
                    .build();
                break;
            default:
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + ANSI_RESET);
        }

        return responsePayload;
    }
}
