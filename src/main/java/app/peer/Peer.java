package app.peer;

import app.Models.PeerInfo;
import app.constants.Constants;
import app.utils.AES;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static app.constants.Constants.TerminalColors.*;

public class Peer {
    private static PeerInfo peerInfo;
    private static SecretKey peerSecretKey;
    private static SecretKey peerLocalSecretKey;
    private static Properties properties = new Properties();

    public static void generateSecretKeyIfNotExists() throws InterruptedException {
        String peerStorageBucketPath = Paths.get("./src/main/resources", peerInfo.getPeer_id()).toString();
        String peerEncryptedFilesPath = Constants.FilePaths.peerEncryptedFilesPath.replace("{peerId}", peerInfo.getPeer_id());

        File keyFile = new File(peerStorageBucketPath + "/keys/key.der");
        File permanentKeyFile = new File(peerStorageBucketPath + "/keys/localKey.der");

        if (!Files.exists(Paths.get(peerStorageBucketPath))) {
            System.out.println(ANSI_YELLOW + String.format("%s: Seen for the first time on the network", peerInfo.getPeer_id()));
            TimeUnit.SECONDS.sleep(1);
            System.out.println("Creating StorageBucket for keys, files" + ANSI_RESET);
            File peerFolder = new File(peerStorageBucketPath);
            peerFolder.mkdir();

            String peerKeysFolderName = peerStorageBucketPath + "/keys";
            File peerKeysFolder = new File(peerKeysFolderName);
            peerKeysFolder.mkdir();

            File peerEncryptedFilesFolder = new File(peerEncryptedFilesPath);
            peerEncryptedFilesFolder.mkdir();
        }

        try {
            if (keyFile.exists()) {
                System.out.println(ANSI_YELLOW + "Loading communication key" + ANSI_RESET);
                byte[] keyBytes = Files.readAllBytes(Paths.get(keyFile.getAbsolutePath()));
                peerSecretKey = AES.getSecretKey(keyBytes);
            } else {
                System.out.println(ANSI_YELLOW + "Generating communication key" + ANSI_RESET);
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecureRandom secureRandom = new SecureRandom();
                keyGen.init(256, secureRandom);
                peerSecretKey = keyGen.generateKey();

                AES.writeKeyToFile(peerSecretKey, peerStorageBucketPath + "/keys/key.der");
            }

            if (permanentKeyFile.exists()) {
                System.out.println(ANSI_YELLOW + "Loading permanent key" + ANSI_RESET);
                byte[] keyBytes = Files.readAllBytes(Paths.get(permanentKeyFile.getAbsolutePath()));
                peerLocalSecretKey = AES.getSecretKey(keyBytes);
            } else {
                System.out.println(ANSI_YELLOW + "Generating permanent key" + ANSI_RESET);
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecureRandom secureRandom = new SecureRandom();
                keyGen.init(256, secureRandom);
                peerLocalSecretKey = keyGen.generateKey();

                AES.writeKeyToFile(peerLocalSecretKey, peerStorageBucketPath + "/keys/localKey.der");
            }
            System.out.println();
            TimeUnit.SECONDS.sleep(1);
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            System.out.println(ANSI_RED + "NoSuchAlgorithmException" + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    public static void serverSocket() {
        try {
            ServerSocket serverSocket = new ServerSocket(peerInfo.getPort_no());

            while (true) {
                Socket clientSocket = serverSocket.accept();

                ClientHandler clientHandler = new ClientHandler(clientSocket, peerInfo.getPeer_id(), peerSecretKey, peerLocalSecretKey, properties);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED+ "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length < 2) {
            System.out.println("Incorrect number of arguments\n");
            System.exit(1);
        }

        peerInfo = new PeerInfo(args[0], Integer.parseInt(args[1]));
        generateSecretKeyIfNotExists();

        properties.load(new FileInputStream("src/main/resources/config.properties"));

        Menu menu = new Menu(peerInfo, peerSecretKey, peerLocalSecretKey, properties);
        Thread thread = new Thread(menu);
        thread.start();

        serverSocket();
    }
}

