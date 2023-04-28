package app.peer;

import app.Models.Payloads.EncryptedPayload;
import app.Models.Payloads.FetchKeyResponsePayload;
import app.Models.Payloads.Payload;
import app.Models.Payloads.Peer.FetchKeyPayload;
import app.Models.Payloads.ResponsePayload;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.utils.AES;
import app.utils.CObject;
import app.utils.RSA;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.Callable;

import static app.constants.Constants.TerminalColors.*;

public class PeerRequester implements Callable<ResponsePayload> {
    private final PeerInfo peerInfo;
    private final PeerInfo requestingPeerInfo;
    private SecretKey requestingPeerKey = null;
    private static Socket peerSocket = null;
    private Payload payload;
    private Socket CASocket = null;
    private Properties properties = new Properties();

    public PeerRequester(PeerInfo peerInfo, PeerInfo requestingPeerInfo, Payload payload) throws IOException {
        this.peerInfo = peerInfo;
        this.requestingPeerInfo = requestingPeerInfo;
        this.payload = payload;
        this.properties.load(new FileInputStream("src/main/resources/config.properties"));
        this.CASocket = new Socket(properties.getProperty("IP_ADDRESS"), Integer.parseInt(properties.getProperty("CA_PORT")));;
    }

    @Override
    public ResponsePayload call() {
        ResponsePayload responsePayload = null;
        try {
            System.out.println(ANSI_YELLOW + String.format("Checking for %s key in KeyCache", requestingPeerInfo.getPeer_id()) + ANSI_RESET);
            // get Peer SecretKey from cache
            requestingPeerKey = PeersSecretKeyCache.getPeerSecretKey(requestingPeerInfo.getPeer_id());

            // if key is not present,
            // perform handshake with CA to obtain key
            if (requestingPeerKey == null) {
                ObjectOutputStream CAWriter = new ObjectOutputStream(CASocket.getOutputStream());
                ObjectInputStream CAReader = new ObjectInputStream(CASocket.getInputStream());

                Payload fetchKeyPayload = new FetchKeyPayload.Builder()
                    .setPeerInfo(peerInfo)
                    .setCommand(Commands.fetchKey.name())
                    .setRequestingPeerId(requestingPeerInfo.getPeer_id())
                    .build();

                System.out.println(ANSI_YELLOW + String.format("Key not found"));
                System.out.println(String.format("Requesting %s key from Certificate Authority", peerInfo.getPeer_id(), requestingPeerInfo.getPeer_id()) + ANSI_RESET);

                CAWriter.writeObject(fetchKeyPayload);
                CAWriter.flush();

                FetchKeyResponsePayload fetchKeyResponsePayload = (FetchKeyResponsePayload) CAReader.readObject();

                if (fetchKeyResponsePayload.getStatusCode() == 200) {
                    byte[] CAPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("CA_PBK"));
                    byte[] encryptedKey = fetchKeyResponsePayload.getKey();
                    byte[] keyBytes = RSA.decrypt(encryptedKey, RSA.getPublicKey(CAPublicKeyBytes));
                    requestingPeerKey = AES.getSecretKey(keyBytes);
                    PeersSecretKeyCache.setPeersSecretKey(requestingPeerInfo.getPeer_id(), requestingPeerKey);
                    System.out.println(ANSI_YELLOW + fetchKeyResponsePayload.getMessage() + ANSI_RESET);
                }

                try {
                    CAWriter.close();
                } catch (IOException e) {
                    System.out.println(ANSI_RED + "IOException: Error closing socket: " + e.getMessage() + ANSI_RESET);
                    e.printStackTrace();
                }
            }

            byte[] encryptedBytes = AES.encrypt(requestingPeerKey, CObject.objectToBytes(payload));
            EncryptedPayload encryptedPayload = new EncryptedPayload();
            encryptedPayload.setData(encryptedBytes);
            encryptedPayload.setPeerInfo(peerInfo);

            peerSocket = new Socket(properties.getProperty("IP_ADDRESS"), requestingPeerInfo.getPort_no());
            System.out.println(ANSI_BLUE + "Connecting to Peer: " + requestingPeerInfo.getPeer_id() + ANSI_RESET);

            ObjectOutputStream peerWriter = new ObjectOutputStream(peerSocket.getOutputStream());
            ObjectInputStream peerReader = new ObjectInputStream(peerSocket.getInputStream());

            peerWriter.writeObject(encryptedPayload);
            peerWriter.flush();

            responsePayload = (ResponsePayload) peerReader.readObject();

            if (responsePayload.getStatusCode() == 200 || responsePayload.getStatusCode() == 201) {
                System.out.println(ANSI_BLUE + responsePayload.getMessage() + ANSI_RESET);
            } else {
                System.out.println(ANSI_RED + responsePayload.getMessage() + ANSI_RESET);
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println(ANSI_RED + "ClassNotFoundException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            System.out.println(ANSI_RED + "InvalidKeySpecException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(ANSI_RED + "NoSuchAlgorithmException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } finally {
            try {
                if (CASocket != null) {
                    CASocket.close();
                }

                if (peerSocket != null) {
                    peerSocket.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "IOException: Error closing socket: " + e.getMessage() + ANSI_RESET);
                e.printStackTrace();
            }
        }
        return responsePayload;
    }
}
