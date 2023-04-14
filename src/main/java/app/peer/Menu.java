package app.peer;

import app.Models.Payloads.InitPayload;
import app.Models.Payloads.Payload;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.constants.Constants;
import app.constants.KeyManager;
import app.utils.AES;
import app.utils.RSA;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Properties;

import static app.constants.Constants.TerminalColors.*;

public class Menu implements Runnable {
    private static Socket FDSSocket = null;
    private static Socket CASocket = null;
    private static String IP_ADDRESS = "127.0.0.1";
    private static int FDS_PORT = 8080;
    private static int CA_PORT = 9000;
    private String peer_ID = null;
    private int port_no;

    public Menu(String PEER_ID, int PORT_NO) {
        this.peer_ID = PEER_ID;
        this.port_no = PORT_NO;
    }

    public static void showMenu() {
        System.out.println(ANSI_YELLOW + "//////////////////////////////////");
        System.out.println("keygen");
        System.out.println("//////////////////////////////////" + ANSI_RESET);
    }

    @Override
    public void run() {
        try {
            // load Properties
            Properties properties = new Properties();
            properties.load(new FileInputStream("src/main/resources/config.properties"));

            FDSSocket = new Socket(IP_ADDRESS, FDS_PORT);
            System.out.println(ANSI_BLUE + "Connected to File Distribution Server" + ANSI_RESET);
            CASocket = new Socket(IP_ADDRESS, CA_PORT);
            System.out.println(ANSI_BLUE + "Connected to Certificate Authority" + ANSI_RESET);

            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            DataInputStream FDSReader = new DataInputStream(new BufferedInputStream(FDSSocket.getInputStream()));
            ObjectOutputStream FDSWriter = new ObjectOutputStream(FDSSocket.getOutputStream());
            ObjectOutputStream CAWriter = new ObjectOutputStream(CASocket.getOutputStream());
            ObjectInputStream CAReader = new ObjectInputStream(CASocket.getInputStream());

            ObjectOutputStream genericWriter = null;

            String peerStorageBucketPath = "./src/main/resources/" + peer_ID;
            File keyFile = new File(peerStorageBucketPath + "/keys/key.der");
            SecretKey key = null;
            if (keyFile.exists()) {
                byte[] keyBytes = Files.readAllBytes(Paths.get(keyFile.getAbsolutePath()));
                key = new SecretKeySpec(keyBytes, "AES");
            } else {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecureRandom secureRandom = new SecureRandom();
                keyGen.init(256, secureRandom);
                SecretKey secretKey = keyGen.generateKey();

                AES.writeKeyToFile(secretKey, peerStorageBucketPath + "/keys/key.der");
            }

            PeerInfo peerInfo = new PeerInfo(peer_ID, port_no);
            byte[] FDSPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("FDS_PBK"));

            InitPayload payload = new InitPayload.Builder()
                .setCommand(Commands.registerPeer.name())
                .setPeerInfo(peerInfo)
                .setKey(RSA.encrypt(key.getEncoded(), RSA.getPublicKey(FDSPublicKeyBytes)))
                .build();
            System.out.println(RSA.getPublicKey(FDSPublicKeyBytes));
            System.out.println(key);
            System.out.println(payload.getKey());

            FDSWriter.writeObject(payload);
            FDSWriter.flush();

            String serverResponse = FDSReader.readUTF();
            System.out.println(ANSI_GREEN + serverResponse + ANSI_RESET);

            byte[] CAPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("CA_PBK"));
            payload = new InitPayload.Builder()
                .setCommand(Commands.registerPeer.name())
                .setPeerInfo(peerInfo)
                .setKey(RSA.encrypt(key.getEncoded(), RSA.getPublicKey(CAPublicKeyBytes)))
                .build();

            CAWriter.writeObject(payload);
            CAWriter.flush();

            String CAResponse = CAReader.readUTF();
            System.out.println(ANSI_GREEN + CAResponse + ANSI_RESET);

            String userInput = null;
            while (true) {
                showMenu();
                System.out.print("> ");
                userInput = consoleReader.readLine();

                if (userInput == null || userInput.equalsIgnoreCase("exit")) {
                    break;
                }

                genericWriter = FDSWriter;

                if (userInput.matches("^keygen.*")) {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    SecureRandom secureRandom = new SecureRandom();
                    keyGen.init(256, secureRandom);
                    SecretKey secretKey = keyGen.generateKey();

                    AES.writeKeyToFile(secretKey, peerStorageBucketPath + "/keys/key.der");

                    payload = new InitPayload.Builder()
                        .setCommand(Commands.registerKey.name())
                        .setKey(RSA.encrypt(secretKey.getEncoded(), RSA.getPublicKey(CAPublicKeyBytes)))
                        .build();

                    properties.load(new FileInputStream("src/main/resources/config.properties"));

                    // override generic writer to write output to CertificateAuthority
                    genericWriter = CAWriter;
                }

                genericWriter.writeObject(payload);
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "Error: " + e.getMessage() + ANSI_RESET);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (FDSSocket != null) {
                    FDSSocket.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "IOException: Error closing socket: " + e.getMessage() + ANSI_RESET);
            }
        }
    }
}
