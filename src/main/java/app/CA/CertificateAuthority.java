package app.CA;

import app.MongoConnectionManager;
import app.constants.Constants;
import app.constants.KeyManager;
import app.utils.RSA;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static app.constants.Constants.TerminalColors.*;
import static app.constants.Constants.TerminalColors.ANSI_RED;

public class CertificateAuthority {
    private static int PORT = 9000;
    private static ServerSocket serverSocket = null;
    static Properties properties = new Properties();

    public static void generateKeysIfNotExists() throws IOException, NoSuchAlgorithmException {
        File keysFolder = new File(Constants.FilePaths.CAKeys);

        if (!keysFolder.exists()) {
            keysFolder.mkdir();
        }

        File privateKeyFile = new File(Constants.FilePaths.CAKeys + "/private.der");
        File publicKeyFile = new File(Constants.FilePaths.CAKeys + "/public.der");

        if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
            KeyPair keyPair = RSA.generateKeyPair(2048);

            FileOutputStream fos = new FileOutputStream(publicKeyFile.getAbsolutePath());
            fos.write(keyPair.getPublic().getEncoded());
            fos.close();
            properties.setProperty("CA_PBK", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            properties.store(new FileOutputStream("src/main/resources/config.properties"), null);

            fos = new FileOutputStream(privateKeyFile.getAbsolutePath());
            fos.write(keyPair.getPrivate().getEncoded());
            fos.close();
        }
    }

    public static void main(String args[]) {
        try {
            // load properties
            properties.load(new FileInputStream("src/main/resources/config.properties"));

            generateKeysIfNotExists();

            new MongoConnectionManager(properties.getProperty("CONNECTION_STRING"), properties.getProperty("DATABASE_NAME"));
            new KeyManager(Constants.FilePaths.CAKeys);

            serverSocket = new ServerSocket(PORT);
            System.out.println(ANSI_BLUE + "Trying to start Certificate Authority on " + PORT + ANSI_RESET);
            TimeUnit.SECONDS.sleep(1);
            System.out.println(ANSI_BLUE + "Server started...\n" + ANSI_RESET);

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
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
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
