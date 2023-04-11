package app.FDS;

import java.io.*;
import java.net.Socket;

import app.Models.PeerInfo;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.ReturnDocument;
import org.bson.Document;
import app.MongoConnectionManager;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

import app.Models.Payload;
import static app.constants.Constants.TerminalColors.*;

class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private ObjectInputStream clientReader;
    private DataOutputStream clientWriter;
    private PeerInfo peerInfo;

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
                PeerInfo peerInfo = clientInput.getPeerInfo();
                this.peerInfo = peerInfo;
                String response = processInput(clientInput);
                clientWriter.writeUTF(response);
                clientWriter.flush();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "Error: " + e.getMessage() + ANSI_RESET);
            MongoDatabase database = MongoConnectionManager.getDatabase();
            MongoCollection<Document> collection = database.getCollection("peer_info");
            Document filter = new Document("peer_id", this.peerInfo.getPeer_id());
            Document update = new Document("$set", new Document("is_active", false));

            collection.findOneAndUpdate(filter, update);
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
        PeerInfo peerInfo = clientPayload.getPeerInfo();
        System.out.println(ANSI_BLUE + "Serving Peer: " + peerInfo.getPeer_id() + ANSI_RESET);

        String[] command = clientPayload.getCommand().split(" ", 2);
        String commandName = command[0];
        switch (commandName) {
            case "init":
                String peer_id = peerInfo.getPeer_id();
                String port_no = String.valueOf(peerInfo.getPort_no());

                MongoDatabase database = MongoConnectionManager.getDatabase();
                MongoCollection<Document> collection = database.getCollection("peer_info");

                Document filter = new Document("peer_id", peer_id);

                Document update = new Document("$set",
                        new Document("port_no", port_no)
                                .append("is_active", true));

                FindOneAndUpdateOptions options = new FindOneAndUpdateOptions();
                options.returnDocument(ReturnDocument.AFTER);

                Document updatedDoc = collection.findOneAndUpdate(filter, update, options);
                if (updatedDoc == null) {
                    System.out.println("Document not found");
                    // Insert a new document with the specified filter and update
                    Document newDocument = new Document("port_no", port_no);
                    newDocument.append("is_active", true);
                    collection.insertOne(newDocument.append("peer_id", peer_id));
                }

                break;
            case "":
                String commandOptions = command[1];
                break;
            default:
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + command + ANSI_RESET);
        }

        System.out.println(ANSI_BLUE + clientPayload.getCommand() + ANSI_RESET);
        return "Server ACK: " + clientPayload.getCommand();
    }
}