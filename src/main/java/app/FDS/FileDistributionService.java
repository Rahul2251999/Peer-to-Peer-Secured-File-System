package app.FDS;

import app.MongoConnectionManager;

import java.net.*;
import java.io.*;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import static app.constants.Constants.TerminalColors.*;

public class FileDistributionService {
    private static int PORT = 8080;
    private static ServerSocket serverSocket = null;

    public static void main(String[] args) {
        try {
            // load properties
            Properties properties = new Properties();
            properties.load(new FileInputStream("src/main/resources/config.properties"));

            new MongoConnectionManager(properties.getProperty("CONNECTION_STRING"), properties.getProperty("DATABASE_NAME"));

            serverSocket = new ServerSocket(PORT);
            System.out.println(ANSI_BLUE + "Trying to start File Distribution Server on " + PORT + ANSI_RESET);
            TimeUnit.SECONDS.sleep(1);
            System.out.println(ANSI_BLUE + "Server started...\n" + ANSI_RESET);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println(ANSI_BLUE + "Client connected: " + clientSocket + ANSI_RESET);

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
        } catch (InterruptedException e) {
            System.out.println(ANSI_RED + "InterruptedException: " + e.getMessage() + ANSI_RESET);
        } finally {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "InterruptedException: Error closing server socket: " + e.getMessage() + ANSI_RESET);
            }
        }
    }
}
