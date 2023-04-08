package com.FDS;

import java.net.*;
import java.io.*;
import java.util.concurrent.TimeUnit;
import static com.constants.Constants.TerminalColors.*;

public class FileDistributionService {
    private static int PORT = 8080;
    private static ServerSocket serverSocket = null;

    public static void main(String[] args) {
        try {
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
