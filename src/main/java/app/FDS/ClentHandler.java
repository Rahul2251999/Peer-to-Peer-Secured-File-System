package app.FDS;

import java.io.*;
import java.net.Socket;
import java.nio.file.Paths;
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
            case "registerKey":
                initPayload = (InitPayload) clientPayload;
                System.out.println(ANSI_BLUE + "Registering key for peer " + peer_id + ANSI_RESET);
                keyBytes = RSA.decrypt(initPayload.getKey(), KeyManager.getPrivateKey());
                key = AES.getSecretKey(keyBytes);
                peerDBItem = peerDBMap.get(peer_id);
                peerDBItem.setKey(key);
                peerDBMap.put(peer_id, peerDBItem);

                response = "FDS: ACK: SecretKey register successfully";
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
                    Map<String, Object> documentMap = new HashMap<>(cursor.next());
                    Map<String, String> permissions = (Map<String, String>) documentMap.get("permissions");
                    String owner = (String) documentMap.get("owner");

                    if (owner.equals(peer_id)
                        || checkPermissions(documentMap, peer_id, "r")
                            || checkPermissions(documentMap, peer_id, "w")
                    || !documentMap.get("name").equals("")) {
                        Date date = ((ObjectId) documentMap.get("_id")).getDate();
                        String formattedDate = new SimpleDateFormat("MMM dd HH:mm").format(date);

                        StringBuilder sb = new StringBuilder();

                        sb.append((boolean) documentMap.get("isDirectory") ? "d" : "-");
                        sb.append(" ");
                        sb.append(owner.equals(peer_id) ? "w" : permissions.get(peer_id));
                        sb.append(" ");
                        sb.append(String.format("%-" + 20 + "s", documentMap.get("owner")));
                        sb.append(String.format("%-" + 15 + "s", formattedDate));
                        sb.append(Paths.get(documentMap.get("parent") + "/" + documentMap.get("name")).normalize());
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
            case "cd":
                ChangeDirectoryPayload changeDirectoryPayload = (ChangeDirectoryPayload) clientPayload;
                String path = Paths.get(changeDirectoryPayload.getPwd() + changeDirectoryPayload.getChangeInto()).normalize().toString();

                collection = db.getCollection("file_metadata");

                Document query = new Document("$expr", new Document("$eq", Arrays.asList(new Document("$concat", Arrays.asList("$parent", "$name")), path)));
                Document document = collection.find(query).first();

                int statusCode;
                if (document != null) {
                    Map<String, Object> documentMap = new HashMap<>(document);

                    // check if the peer has read or write permissions over the directory
                    if (checkPermissions(documentMap, peerInfo.getPeer_id(), "r") ||
                        checkPermissions(documentMap, peerInfo.getPeer_id(), "w") ||
                        documentMap.get("owner").equals(peerInfo.getPeer_id())) {
                        message = "";
                        statusCode = 200;
                    } else {
                        message = String.format("%s: Access denied", path);
                        statusCode = 401;
                    }
                } else {
                    message = String.format("%s: Not found", path);
                    statusCode = 404;
                }
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(statusCode)
                    .setMessage(message)
                    .build();
                break;
            default:
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(400)
                    .setMessage("FDS: Command handler not found")
                    .build();
                System.out.println(ANSI_YELLOW + "Invalid command issued: " + commandName + ANSI_RESET);
        }

        return responsePayload;
    }

    private ResponsePayload registerFile(MongoDatabase db, CreateFilePayload createFilePayload, boolean isDirectory) {
        ResponsePayload responsePayload;

        String message;
        int statusCode;
        String parent = createFilePayload.getParent();
        Map<String, Integer> toBeReplicatedPeers = null;

        // get Collection
        MongoCollection<Document> collection = db.getCollection("file_metadata");

        Document query = new Document("$expr", new Document("$eq", Arrays.asList(new Document("$concat", Arrays.asList("$parent", "$name")), parent)));
        Document document = collection.find(query).first();

        Map<String, Object> documentMap = new HashMap<>(document);
        boolean hasPermission = checkPermissions(documentMap, peerInfo.getPeer_id(), "w")
            || documentMap.get("owner").equals(peerInfo.getPeer_id());

        // the parent where the file is being created should not be deleted
        // the peer should have permissions to create the file in the parent
        // or it should be root directory (every peer can create a file/folder in root)
        if ((!(boolean) documentMap.get("isDeleted")) && (parent.equals("/") || hasPermission)) {
            String[] activePeers = peerDBMap.values()
                .stream()
                .filter(PeerDB::isActive)
                .map(PeerDB::getPeer_id)
                .toArray(String[]::new);
            Set<String> uniqueRandomPeers = RandomUniquePicker.pick(activePeers, Integer.parseInt(this.properties.getProperty("REPLICATION_FACTOR")));

            // In case `RandomUniquePicker.pick` missed it, add owner peer
            uniqueRandomPeers.add(peerInfo.getPeer_id());
            toBeReplicatedPeers = uniqueRandomPeers.stream()
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
                toBeReplicatedPeers = null;
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
            .setToBeReplicatedPeers(toBeReplicatedPeers)
            .build();

        return responsePayload;
    }

    public boolean checkPermissions(Map<String, Object> documentMap, String peerId, String permissionType) {
        Map<String, String> permissions = (Map<String, String>) documentMap.get("permissions");
        String permission = permissions.get(peerId);

        // if no permissions
        // allow the user
        if (permission == null) {
            return true;
        }

        return permission.equals(permissionType);
    }
}