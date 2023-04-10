package com.FDS;

import com.payloads.Payload;

import java.io.*;
import java.net.Socket;

import static com.constants.Constants.TerminalColors.*;

class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private ObjectInputStream clientReader;
    private DataOutputStream clientWriter;

    public ClientHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try {
            System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + "\n" + ANSI_RESET);

            clientReader = new ObjectInputStream(clientSocket.getInputStream());
            clientWriter = new DataOutputStream(clientSocket.getOutputStream());

            Payload clientInput;
            while ((clientInput = (Payload) clientReader.readObject()) != null) {
                String response = processInput(clientInput);
                clientWriter.writeUTF(response);
                clientWriter.flush();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "Error: " + e.getMessage() + ANSI_RESET);
        } catch (ClassNotFoundException e) {
            System.out.println(ANSI_RED + "ClassNotFoundException: " + e.getMessage() + ANSI_RESET);
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
                System.out.println(ANSI_RED + "Error closing client socket: " + e.getMessage() + ANSI_RESET);
            }
        }
    }

    private String processInput(Payload clientPayload) {
        System.out.println(ANSI_BLUE + "Serving Peer: " + clientPayload.getPeerId() + ANSI_RESET);

        String command = clientPayload.getCommand();

        switch (command){
            case "init":
                String peer_id = clientPayload.getPeerId();
                String port_no = String.valueOf(clientPayload.getPortNo());
                System.out.println(peer_id + " " + port_no);
                break;
            default:
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + command + ANSI_RESET);
        }

        System.out.println(ANSI_BLUE + clientPayload.getCommand() + ANSI_RESET);
        return "Server ACK: " + clientPayload.getCommand();
    }
}