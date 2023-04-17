package app.FDS;

import java.io.*;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import app.Models.Payloads.Peer.ListFilesResponsePayload;
import app.utils.RandomUniquePicker;
import com.mongodb.MongoWriteException;
import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import org.bson.Document;
import static com.mongodb.client.model.Filters.eq;

import app.Models.Payloads.*;
import app.MongoConnectionManager;
import app.constants.KeyManager;
import app.utils.AES;
import app.utils.CObject;
import app.utils.RSA;
import com.mongodb.client.MongoDatabase;

import app.Models.PeerDB;
import app.Models.PeerInfo;
import org.bson.types.ObjectId;

import javax.crypto.SecretKey;

import static app.constants.Constants.TerminalColors.*;

class ClientHandler implements Runnable {
    private final Socket clientSocket;
    private ObjectInputStream clientReader;
    private ObjectOutputStream clientWriter;
    private PeerInfo peerInfo;
    private static Map<String, PeerDB> peerDBMap = new HashMap<>();
    private final Properties properties;

    public ClientHandler(Socket clientSocket, Properties properties) {
        this.clientSocket = clientSocket;
        this.properties = properties;
    }

    @Override
    public void run() {
        try {
            System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + "\n" + ANSI_RESET);

            clientReader = new ObjectInputStream(clientSocket.getInputStream());
            clientWriter = new ObjectOutputStream(clientSocket.getOutputStream());

            Object clientInput;
            while ((clientInput = clientReader.readObject()) != null) {
                PeerInfo peerInfo = null;
                Payload payload = null;
                if (clientInput instanceof EncryptedPayload encryptedPayload) {
                    peerInfo = encryptedPayload.getPeerInfo();
                    byte[] decryptedData = AES.decrypt(peerDBMap.get(peerInfo.getPeer_id()).getKey(), encryptedPayload.getData());
                    payload = (Payload) CObject.bytesToObject(decryptedData);
                } else if (clientInput instanceof Payload) {
                    payload = (Payload) clientInput;
                    peerInfo = payload.getPeerInfo();
                }
                this.peerInfo = peerInfo;

                if (payload != null) {
                    ResponsePayload response = processInput(payload);
                    clientWriter.writeObject(response);
                    clientWriter.flush();
                }
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "Error: " + e.getMessage() + ANSI_RESET);
            PeerDB peerDBItem = peerDBMap.get(this.peerInfo.getPeer_id());
            peerDBItem.setActive(false);
            peerDBMap.put(this.peerInfo.getPeer_id(), peerDBItem);

            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            System.out.println(ANSI_RED + "ClassNotFoundException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
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
                System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
                e.printStackTrace();
            }
        }
    }

    private ResponsePayload processInput(Payload clientPayload) throws Exception {
        PeerInfo peerInfo = clientPayload.getPeerInfo();
        String peer_id = peerInfo.getPeer_id();
        System.out.println(ANSI_BLUE + "Serving Peer: " + peer_id);
        System.out.println("Executing: " + clientPayload.getCommand() + ANSI_RESET);

        ResponsePayload responsePayload = null;
        MongoDatabase db = MongoConnectionManager.getDatabase();

        String commandName = clientPayload.getCommand();
        switch (commandName) {
            case "registerPeer":
                InitPayload initPayload = (InitPayload) clientPayload;
                byte[] keyBytes = RSA.decrypt(initPayload.getKey(), KeyManager.getPrivateKey());
                SecretKey key = AES.getSecretKey(keyBytes);

                PeerDB peerDBItem = new PeerDB(peerInfo, true, key);
                peerDBMap.put(peer_id, peerDBItem);

                String response = "Peer registered Successfully";
                responsePayload = new ResponsePayload.Builder()
                        .setStatusCode(200)
                        .setMessage(response)
                        .build();
                break;
            case "mkdir":
                CreateFilePayload createFilePayload = (CreateFilePayload) clientPayload;

                responsePayload = registerFile(db, createFilePayload, true);

                break;
            case "touch":
                createFilePayload = (CreateFilePayload) clientPayload;

                responsePayload = registerFile(db, createFilePayload, false);

                break;
            case "ls":
                ListFilesPayload listFilesPayload = (ListFilesPayload) clientPayload;

                // check for starts with
                Pattern pattern = Pattern.compile("^" + listFilesPayload.getPwd() + ".*");

                // get Collection
                MongoCollection<Document> collection = db.getCollection("file_metadata");

                FindIterable<Document> results = collection.find(new Document("parent", pattern));
                MongoCursor<Document> cursor = results.iterator();
                List<String> allLines = new ArrayList<>();
                while (cursor.hasNext()) {
                    Map<String, Object> document = new HashMap<>(cursor.next());
                    Map<String, String> permissions = (Map<String, String>) document.get("permissions");
                    String owner = (String) document.get("owner");

                    if (owner.equals(peer_id) || (permissions != null && permissions.getOrDefault(peer_id, null) != null)) {
                        Date date = ((ObjectId) document.get("_id")).getDate();
                        String formattedDate = new SimpleDateFormat("MMM dd HH:mm").format(date);

                        StringBuilder sb = new StringBuilder();

                        sb.append((boolean) document.get("isDirectory") ? "d" : "-");
                        sb.append(" ");
                        sb.append(owner.equals(peer_id) ? "w" : permissions.get(peer_id));
                        sb.append(" ");
                        sb.append(String.format("%-" + 20 + "s", document.get("owner")));
                        sb.append(String.format("%-" + 15 + "s", formattedDate));
                        sb.append(document.get("parent") + (String) document.get("name"));
                        allLines.add(sb.toString());
                    }
                }

                String message = String.format("%d: files/directories found", allLines.size());
                responsePayload = new ListFilesResponsePayload.Builder()
                    .setLines(allLines)
                    .setStatusCode(200)
                    .setMessage(message)
                    .build();
                break;
            default:
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + commandName + ANSI_RESET);
        }

        return responsePayload;
    }

    private ResponsePayload registerFile(MongoDatabase db, CreateFilePayload createFilePayload, boolean isDirectory) {
        ResponsePayload responsePayload;

        String message;
        int statusCode;
        String parent = createFilePayload.getParent();
        Map<String, Integer> replicatedPeerPorts = null;

        // get Collection
        MongoCollection<Document> collection = db.getCollection("file_metadata");

        Document document = collection.find(eq("parent", parent)).first();
        Map<String, Object> hashMap = new HashMap<>(document);
        boolean hasPermission = checkPermissions(hashMap, peerInfo.getPeer_id());

        if ((!(boolean) hashMap.get("isDeleted")) && (parent.equals("/") || hasPermission)) {
            String[] activePeers = peerDBMap.values()
                .stream()
                .filter(PeerDB::isActive)
                .map(PeerDB::getPeer_id)
                .toArray(String[]::new);
            Set<String> uniqueRandomPeers = RandomUniquePicker.pick(activePeers, Integer.parseInt(this.properties.getProperty("REPLICATION_FACTOR")));

            // In case `RandomUniquePicker.pick` missed it, add owner peer
            uniqueRandomPeers.add(peerInfo.getPeer_id());
            replicatedPeerPorts = uniqueRandomPeers.stream()
                .filter(peerDBMap::containsKey)
                .collect(Collectors.toMap(Function.identity(), peer -> peerDBMap.get(peer).getPort_no()));

            // create new Document
            document = new Document();
            document.append("name", createFilePayload.getFileName());
            document.append("owner", this.peerInfo.getPeer_id());
            document.append("parent", createFilePayload.getParent());
            document.append("permissions", createFilePayload.getAccessList());
            document.append("isDirectory", isDirectory);
            document.append("isDeleted", false);
            document.append("replicatedPeers", uniqueRandomPeers);

            try {
                // insert document into collection
                collection.insertOne(document);

                message = String.format("`%s` registered on network", createFilePayload.getFileName());
                statusCode = 201;
            } catch (MongoWriteException e) {
                message = "Unknown Exception caused while writing to MongoDB";
                statusCode = 400;
                replicatedPeerPorts = null;
                if (e.getCode() == 11000) {
                    message = String.format("`%s` already exists on the network", createFilePayload.getFileName());
                    statusCode = 409;
                }
            }
        } else {
            message = String.format("`%s` do not have permissions to create file at `%s`",
                    peerInfo.getPeer_id(), parent);
            statusCode = 401;
        }

        responsePayload = new CreateFileResponsePayload.Builder()
            .setStatusCode(statusCode)
            .setMessage(message)
            .setReplicatedPeerPorts(replicatedPeerPorts)
            .build();

        return responsePayload;
    }

    public boolean checkPermissions(Map<String, Object> hashMap, String peerId) {
        Map<String, String> permissions = (Map<String, String>) hashMap.get("permissions");
        String permission = permissions.get(peerId);

        return permission.equals("w");
    }
}