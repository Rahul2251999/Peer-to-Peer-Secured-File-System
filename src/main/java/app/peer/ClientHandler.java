package app.peer;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

import static app.constants.Constants.TerminalColors.*;

class ClientHandler implements Runnable {
    private Socket clientSocket;
    private String PEER_ID;
    private DataInputStream clientReader;
    private DataOutputStream clientWriter;

    public ClientHandler(Socket clientSocket, String PEER_ID) {
        this.clientSocket = clientSocket;
        this.PEER_ID = PEER_ID;
    }

    @Override
    public void run() {
        try {
            System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + ANSI_RESET);

            clientReader = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            clientWriter = new DataOutputStream(clientSocket.getOutputStream());

            String clientInput;
            while ((clientInput = clientReader.readUTF()) != null) {
                String response = processInput(clientInput);
                clientWriter.writeUTF(response);
                clientWriter.flush();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
                if (clientReader != null) {
                    clientReader.close();
                }
                if (clientWriter != null) {
                    clientWriter.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "IOException: Error closing client socket: " + e.getMessage() + ANSI_RESET);
            }
        }
    }

    private String processInput(String input) {
        System.out.println(input);
        return PEER_ID + " ACK: " + input;
    }
}
