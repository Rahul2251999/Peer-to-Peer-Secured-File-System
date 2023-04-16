package app.peer;

import app.Models.PeerInfo;
import app.utils.AES;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static app.constants.Constants.TerminalColors.*;

public class Peer {
    private static PeerInfo peerInfo;
    private static SecretKey peerSecretKey;

    public static void generateSecretKeyIfNotExists() {
        String peerStorageBucketPath = "./src/main/resources/" + peerInfo.getPeer_id();
        File keyFile = new File(peerStorageBucketPath + "/keys/key.der");

        try {
            if (keyFile.exists()) {
                byte[] keyBytes = Files.readAllBytes(Paths.get(keyFile.getAbsolutePath()));
                peerSecretKey = AES.getSecretKey(keyBytes);
            } else {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                SecureRandom secureRandom = new SecureRandom();
                keyGen.init(256, secureRandom);
                peerSecretKey = keyGen.generateKey();

                AES.writeKeyToFile(peerSecretKey, peerStorageBucketPath + "/keys/key.der");
            }
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

                ClientHandler clientHandler = new ClientHandler(clientSocket, peerInfo.getPeer_id());
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED+ "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.out.println("Incorrect number of arguments\n");
            System.exit(1);
        }

        peerInfo = new PeerInfo(args[0], Integer.parseInt(args[1]));

        String peerFolderName = "./src/main/resources/" + peerInfo.getPeer_id();
        File folder = new File(peerFolderName);
        folder.mkdir();
        folder = new File(peerFolderName + "/FDS");
        folder.mkdir();

        Menu menu = new Menu(peerInfo, peerSecretKey);
        Thread thread = new Thread(menu);thread.start();

        serverSocket();
    }
}

