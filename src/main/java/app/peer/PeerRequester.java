package app.peer;

import app.Models.Payloads.EncryptedPayload;
import app.Models.Payloads.FetchKeyResponsePayload;
import app.Models.Payloads.Payload;
import app.Models.Payloads.Peer.CreateFilePayload;
import app.Models.Payloads.Peer.FetchKeyPayload;
import app.Models.Payloads.ResponsePayload;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.utils.AES;
import app.utils.CObject;
import app.utils.RSA;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

import static app.constants.Constants.TerminalColors.*;

public class PeerRequester extends CreateFilePayload implements Runnable {
    private PeerInfo peerInfo;
    private PeerInfo requestingPeerInfo;
    private SecretKey requestingPeerKey = null;
    private static Socket peerSocket = null;
    Payload payload;
    private Socket CASocket = null;
    Properties properties;

    public PeerRequester(PeerInfo peerInfo, PeerInfo requestingPeerInfo, Payload payload, Socket CASocket, Properties properties) {
        this.peerInfo = peerInfo;
        this.requestingPeerInfo = requestingPeerInfo;
        this.payload = payload;
        this.CASocket = CASocket;
        this.properties = properties;
    }

    @Override
    public void run() {
        requestingPeerKey = PeersSecretKeyManager.getPeerSecretKey(requestingPeerInfo.getPeer_id());

        try {
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

                CAWriter.writeObject(fetchKeyPayload);
                CAWriter.flush();

                FetchKeyResponsePayload responsePayload = (FetchKeyResponsePayload) CAReader.readObject();

                if (responsePayload.getStatusCode() == 200) {
                    byte[] CAPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("CA_PBK"));
                    byte[] encryptedKey = responsePayload.getKey();
                    byte[] keyBytes = RSA.decrypt(encryptedKey, RSA.getPublicKey(CAPublicKeyBytes));
                    requestingPeerKey = AES.getSecretKey(keyBytes);
                    PeersSecretKeyManager.setPeersSecretKey(requestingPeerInfo.getPeer_id(), requestingPeerKey);
                }
            }

            byte[] encryptedBytes = AES.encrypt(requestingPeerKey, CObject.objectToBytes(payload));
            EncryptedPayload encryptedPayload = new EncryptedPayload();
            encryptedPayload.setData(encryptedBytes);
            encryptedPayload.setPeerInfo(peerInfo);

            peerSocket = new Socket(properties.getProperty("IP_ADDRESS"), requestingPeerInfo.getPort_no());
            System.out.println(ANSI_BLUE + "Connected to Peer: " + requestingPeerInfo.getPeer_id() + ANSI_RESET);

            ObjectOutputStream peerWriter = new ObjectOutputStream(peerSocket.getOutputStream());
            ObjectInputStream peerReader = new ObjectInputStream(peerSocket.getInputStream());

            peerWriter.writeObject(encryptedPayload);
            peerWriter.flush();

            ResponsePayload responsePayload = (ResponsePayload) peerReader.readObject();

            if (responsePayload.getStatusCode() == 200 || responsePayload.getStatusCode() == 201) {
                System.out.println(ANSI_BLUE + responsePayload.getMessage() + ANSI_RESET);
            } else {
                System.out.println(ANSI_RED + responsePayload.getMessage() + ANSI_RESET);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
