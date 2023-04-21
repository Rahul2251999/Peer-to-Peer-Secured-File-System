package app.CA;

import app.Models.Payloads.*;
import app.Models.Payloads.Peer.FetchKeyPayload;
import app.Models.Payloads.Peer.UpdateKeyPayload;
import app.Models.PeerDB;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.constants.Constants;
import app.constants.KeyManager;
import app.utils.AES;
import app.utils.CObject;
import app.utils.RSA;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static app.constants.Constants.TerminalColors.*;

public class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private ObjectInputStream clientReader;
    private ObjectOutputStream clientWriter;
    private PeerInfo peerInfo;
    private static final Map<String, PeerDB> peerDBMap = new HashMap<>();
    private static Properties properties;

    public ClientHandler(Socket clientSocket, Properties properties) {
        this.clientSocket = clientSocket;
        this.properties = properties;
    }

    @Override
    public void run() {
        try {
            System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + "\n" + ANSI_RESET);

            clientReader = new ObjectInputStream(clientSocket.getInputStream());
            clientWriter = new ObjectOutputStream(clientSocket.getOutputStream());

            Object clientInput;
            while ((clientInput = clientReader.readObject()) != null) {
                PeerInfo peerInfo = null;
                Payload payload = null;
                if (clientInput instanceof EncryptedPayload encryptedPayload) {
                    peerInfo = encryptedPayload.getPeerInfo();
                    byte[] decryptedData = AES.decrypt(peerDBMap.get(peerInfo.getPeer_id()).getKey(), encryptedPayload.getData());
                    payload = (Payload) CObject.bytesToObject(decryptedData);
                } else if (clientInput instanceof Payload) {
                    payload = (Payload) clientInput;
                    peerInfo = payload.getPeerInfo();
                }
                this.peerInfo = peerInfo;

                if (payload != null) {
                    ResponsePayload response = processInput(payload);
                    clientWriter.writeObject(response);
                    clientWriter.flush();
                }
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            PeerDB peerDBItem = peerDBMap.get(this.peerInfo.getPeer_id());
            peerDBItem.setActive(false);
            peerDBMap.put(this.peerInfo.getPeer_id(), peerDBItem);

            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println(ANSI_RED + "ClassNotFoundException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    public static ResponsePayload processInput(Payload clientPayload) throws Exception {
        PeerInfo peerInfo = clientPayload.getPeerInfo();
        String peer_id = peerInfo.getPeer_id();
        System.out.println(ANSI_BLUE + "Serving Peer: " + peer_id);
        System.out.println("Executing: " + clientPayload.getCommand() + ANSI_RESET + "\n");

        ResponsePayload responsePayload = null;

        String[] command = clientPayload.getCommand().split(" ", 2);
        String commandName = command[0];
        switch (commandName) {
            case "registerPeer":
                InitPayload initPayload = (InitPayload) clientPayload;
                byte[] keyBytes = RSA.decrypt(initPayload.getKey(), KeyManager.getPrivateKey());
                SecretKey key = AES.getSecretKey(keyBytes);

                PeerDB peerDBItem = new PeerDB(peerInfo, true, key);
                peerDBMap.put(peer_id, peerDBItem);

                String response = "Peer registered Successfully";
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(200)
                    .setMessage(response)
                    .build();
                break;
            case "registerKey":
                initPayload = (InitPayload) clientPayload;
                System.out.println(ANSI_BLUE + "Registering key for peer " + peer_id + ANSI_RESET);
                keyBytes = RSA.decrypt(initPayload.getKey(), KeyManager.getPrivateKey());
                key = AES.getSecretKey(keyBytes);
                peerDBItem = peerDBMap.get(peer_id);
                peerDBItem.setKey(key);
                peerDBMap.put(peer_id, peerDBItem);

                keyBytes = RSA.encrypt(key.getEncoded(), KeyManager.getPrivateKey());
                UpdateKeyPayload updateKeyPayload = new UpdateKeyPayload.Builder()
                    .setCommand(Commands.updateKey.name())
                    .setPeerInfo(peerInfo)
                    .setKey(keyBytes)
                    .build();

                int successfulyKeyRegistrationCount = 0;
                StringBuilder keyRegistrationSuccessful = new StringBuilder();
                for (Map.Entry<String, PeerDB> peerDBItem1: peerDBMap.entrySet()) {
                    // check if the peer is active and
                    // do not send the payload to the peer requesting keygen
                    if (peerDBItem1.getValue().isActive() && !peerDBItem1.getKey().equals(peerInfo.getPeer_id())) {
                        Socket peerSocket = new Socket(properties.getProperty("IP_ADDRESS"), peerDBItem1.getValue().getPort_no());
                        ObjectOutputStream peerWriter = new ObjectOutputStream(peerSocket.getOutputStream());
                        ObjectInputStream peerReader = new ObjectInputStream(peerSocket.getInputStream());

                        peerWriter.writeObject(updateKeyPayload);
                        peerWriter.flush();

                        responsePayload = (ResponsePayload) peerReader.readObject();

                        if (Constants.ErrorClasses.twoHundredClass.contains(responsePayload.getStatusCode())) {
                            System.out.println(ANSI_BLUE + responsePayload.getMessage() + ANSI_RESET);
                            keyRegistrationSuccessful.append(peerDBItem1.getKey() + ", ");
                            successfulyKeyRegistrationCount += 1;
                        } else {
                            System.out.println(ANSI_RED + responsePayload.getMessage() + ANSI_RESET);
                        }
                        System.out.println();
                    }
                }

                response = successfulyKeyRegistrationCount > 0 ? String.format("CA: ACK: SecretKey registration successfully on %s", keyRegistrationSuccessful.substring(0, keyRegistrationSuccessful.length() - 2)) : String.format("CA: ACK: SecretKey registration failed");
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(200)
                    .setMessage(response)
                    .build();

                break;
            case "fetchKey":
                FetchKeyPayload fetchKeyPayload = (FetchKeyPayload) clientPayload;
                String fetchKeyOf = fetchKeyPayload.getRequestingPeerId();
                System.out.println(ANSI_BLUE + "Fetching Key for peer " + fetchKeyOf + ANSI_RESET);
                int statusCode;
                String message;
                keyBytes = null;

                if (peerDBMap.containsKey(fetchKeyOf)) {
                    peerDBItem = peerDBMap.get(fetchKeyOf);
                    if (peerDBItem.isActive()) {
                        statusCode = 200;
                        message = "Handshake Successful!";
                        keyBytes = RSA.encrypt(peerDBItem.getKey().getEncoded(), KeyManager.getPrivateKey());
                    } else {
                        statusCode = 400;
                        message = "Peer inactive";
                    }
                } else {
                    statusCode = 404;
                    message = "Peer not found";
                }

                responsePayload = new FetchKeyResponsePayload.Builder()
                    .setStatusCode(statusCode)
                    .setMessage(message)
                    .setKey(keyBytes)
                    .build();
                break;
            default:
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(400)
                    .setMessage("CA: Command handler not found")
                    .build();
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + ANSI_RESET);
        }

        return responsePayload;
    }
}
