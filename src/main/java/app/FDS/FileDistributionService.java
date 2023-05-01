package app.FDS;

import java.net.*;
import java.io.*;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import app.MongoConnectionManager;
import app.constants.Constants;
import app.constants.KeyManager;
import app.utils.RSA;

import static app.constants.Constants.TerminalColors.*;

public class FileDistributionService {
    private static ServerSocket serverSocket = null;
    static Properties properties = new Properties();

    public static void generateKeysIfNotExists() throws IOException, NoSuchAlgorithmException {
        File keysFolder = new File(Constants.FilePaths.FDSKeys);

        if (!keysFolder.exists()) {
            keysFolder.mkdir();
        }

        File privateKeyFile = new File(Constants.FilePaths.FDSKeys + "/private.der");
        File publicKeyFile = new File(Constants.FilePaths.FDSKeys + "/public.der");

        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            KeyPair keyPair = RSA.generateKeyPair(2048);

            FileOutputStream fos = new FileOutputStream(publicKeyFile.getAbsolutePath());
            fos.write(keyPair.getPublic().getEncoded());
            fos.close();
            properties.setProperty("FDS_PBK", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            properties.store(new FileOutputStream("src/main/resources/config.properties"), null);

            fos = new FileOutputStream(privateKeyFile.getAbsolutePath());
            fos.write(keyPair.getPrivate().getEncoded());
            fos.close();
        }
    }

    public static void main(String[] args) {
        try {
            // load properties
            properties.load(new FileInputStream("src/main/resources/config.properties"));

            generateKeysIfNotExists();

            new MongoConnectionManager(properties.getProperty("CONNECTION_STRING"), properties.getProperty("DATABASE_NAME"));
            new KeyManager(Constants.FilePaths.FDSKeys);

            serverSocket = new ServerSocket(Integer.parseInt(properties.getProperty("FDS_PORT")));
            System.out.println(ANSI_BLUE + "Trying to start File Distribution Server on " + properties.getProperty("FDS_PORT") + ANSI_RESET);
            TimeUnit.SECONDS.sleep(1);
            System.out.println(ANSI_BLUE + "Server started...\n" + ANSI_RESET);

            MaliciousActivityDetector maliciousActivityDetector = new MaliciousActivityDetector(properties);
            Thread maliciousActivityDetectorThread = new Thread(maliciousActivityDetector);
            maliciousActivityDetectorThread.start();

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println(ANSI_BLUE + "Client connected: " + clientSocket + ANSI_RESET);

                ClientHandler clientHandler = new ClientHandler(clientSocket, properties);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (InterruptedException e) {
            System.out.println(ANSI_RED + "InterruptedException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } finally {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "IOException: Error closing server socket: " + e.getMessage() + ANSI_RESET);
                e.printStackTrace();
            }
        }
    }
}
