package com.peer;

import com.payloads.Payload;

import java.io.*;
import java.net.Socket;

import static com.constants.Constants.TerminalColors.ANSI_BLUE;
import static com.constants.Constants.TerminalColors.ANSI_RESET;

public class Menu implements Runnable {
    private static Socket socket = null;
    private static String IP_ADDRESS = "127.0.0.1";
    private static int FDS_PORT = 8080;
    private String peer_ID = null;

    public Menu(String peer_ID) {
        this.peer_ID = peer_ID;
    }

    @Override
    public void run() {
        try {
            socket = new Socket(IP_ADDRESS, FDS_PORT);
            System.out.println(ANSI_BLUE + "Connected to server" + ANSI_RESET);

            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            DataInputStream serverReader = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            ObjectOutputStream serverWriter = new ObjectOutputStream(socket.getOutputStream());

            String userInput;
            while (true) {
                System.out.print("> ");
                userInput = consoleReader.readLine();
                if (userInput == null || userInput.equalsIgnoreCase("exit")) {
                    break;
                }
                Payload payload = new Payload.Builder()
                                    .setCommand(userInput)
                                    .setPeerId(peer_ID)
                                    .build();
                serverWriter.writeObject(payload);
                serverWriter.flush();

                socket.setSoTimeout(2000);
                String serverResponse = serverReader.readUTF();
                System.out.println(serverResponse);
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                System.out.println("Error closing socket: " + e.getMessage());
            }
        }
    }
}
