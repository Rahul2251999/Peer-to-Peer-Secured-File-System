package app.peer;

import app.Models.Payloads.*;
import app.Models.Payloads.Peer.ReadFilePayload;
import app.Models.Payloads.Peer.UpdateFilePayload;
import app.Models.Payloads.Peer.UpdateKeyPayload;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.constants.Constants;
import app.utils.*;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static app.constants.Constants.TerminalColors.*;

class ClientHandler implements Runnable {
    private Socket clientSocket;
    private String PEER_ID;
    private ObjectInputStream clientReader;
    private ObjectOutputStream clientWriter;
    private SecretKey peerSecretKey;
    private SecretKey peerLocalSecretKey;
    private String peerEncryptedFilesPath;
    private Properties properties;

    public ClientHandler(Socket clientSocket, String PEER_ID, SecretKey peerSecretKey, SecretKey peerLocalSecretKey, Properties properties) {
        this.clientSocket = clientSocket;
        this.PEER_ID = PEER_ID;
        this.peerSecretKey = peerSecretKey;
        this.peerLocalSecretKey = peerLocalSecretKey;
        this.peerEncryptedFilesPath = Constants.FilePaths.peerEncryptedFilesPath.replace("{peerId}", PEER_ID);
        this.properties = properties;
    }

    @Override
    public void run() {
        try {
            // System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + ANSI_RESET);

            clientWriter = new ObjectOutputStream(clientSocket.getOutputStream());
            clientReader = new ObjectInputStream(clientSocket.getInputStream());

            Object clientInput;
            while ((clientInput = clientReader.readObject()) != null) {
                Payload payload = null;
                if (clientInput instanceof EncryptedPayload encryptedPayload) {
                    byte[] decryptedData = AES.decrypt(peerSecretKey, encryptedPayload.getData());
                    payload = (Payload) CObject.bytesToObject(decryptedData);
                } else if (clientInput instanceof Payload) {
                    payload = (Payload) clientInput;
                }

                if (payload != null) {
                    ResponsePayload response = processInput(payload);
                    clientWriter.writeObject(response);
                    clientWriter.flush();
                }
            }
        } catch (IOException e) {
            if (e.getMessage() != null) {
                System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
                e.printStackTrace();
            }
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
                System.out.println(ANSI_RED + "IOException: Error closing client socket: " + e.getMessage() + ANSI_RESET);
                e.printStackTrace();
            }
        }
    }

    private ResponsePayload processInput(Payload clientPayload) throws Exception {
        PeerInfo peerInfo = clientPayload.getPeerInfo();
        String peer_id = peerInfo.getPeer_id();
        String command = clientPayload.getCommand();

        if (!command.equals(Commands.fileListing.name())) {
            System.out.println(ANSI_BLUE + "Serving Peer: " + peer_id);
            System.out.println("Executing: " + command + ANSI_RESET);
        }

        ResponsePayload responsePayload = null;
        String message;

        switch (command) {
            // @deprecated
            case "mkdir":
                CreateFilePayload createFilePayload = (CreateFilePayload) clientPayload;
                byte[] encryptedFolderName = AES.encrypt(peerLocalSecretKey, createFilePayload.getFileName().getBytes());
                File folder = new File(Paths.get(peerEncryptedFilesPath, encryptedFolderName.toString()).toString());
                folder.mkdir();

                message = String.format("Folder created successfully %s", createFilePayload.getFileName());
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(201)
                    .setMessage(message)
                    .build();
                break;
            case "updatePeerKey":
                UpdateKeyPayload updateKeyPayload = (UpdateKeyPayload) clientPayload;
                byte[] CAPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("CA_PBK"));
                SecretKey secretKey = AES.getSecretKey(RSA.decrypt(updateKeyPayload.getKey(), RSA.getPublicKey(CAPublicKeyBytes)));

                PeersSecretKeyCache.setPeersSecretKey(updateKeyPayload.getPeerInfo().getPeer_id(), secretKey);

                message = String.format("%s ACK: %s key updated!", PEER_ID, updateKeyPayload.getPeerInfo().getPeer_id());
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(200)
                    .setMessage(message)
                    .build();
                break;
            case "restore":
            case "touch":
                UpdateFilePayload updateFilePayload = (UpdateFilePayload) clientPayload;

                responsePayload = FileOperations.touch(updateFilePayload, PEER_ID, peerLocalSecretKey, peerEncryptedFilesPath);
                break;
            case "read":
                ReadFilePayload readFilePayload = (ReadFilePayload) clientPayload;

                responsePayload = FileOperations.read(readFilePayload, peerLocalSecretKey, peerEncryptedFilesPath);
                break;
            case "rm":
                DeleteFilePayload deleteFilePayload = (DeleteFilePayload) clientPayload;
                String absoluteFileName = Paths.get(deleteFilePayload.getParent(), deleteFilePayload.getFileName()).normalize().toString();

                responsePayload = FileOperations.delete(absoluteFileName, PEER_ID, peerLocalSecretKey, peerEncryptedFilesPath);
                break;
            case "fileListing":
                FileListingPayload fileListingPayload = (FileListingPayload) clientPayload;
                Set<String> filesThatShouldExists = fileListingPayload.getFiles();
                Set<String> filesFound = FileOperations.getPlainTextPaths(peerEncryptedFilesPath, peerLocalSecretKey);

                Set<String> deletions = new HashSet<>(filesThatShouldExists);
                deletions.removeAll(filesFound);

                HashSet<String> additions = new HashSet<>(filesFound);
                additions.removeAll(filesThatShouldExists);

                for (String file: additions) {
                    FileOperations.delete(file, peerEncryptedFilesPath);
                }

                int statusCode;

                if (deletions.size() > 0) {
                    statusCode = 400;
                } else {
                    statusCode = 200;
                }

                responsePayload = new FileListingResponsePayload.Builder()
                    .setStatusCode(statusCode)
                    .setUnTraceableFiles(deletions)
                    .build();
                break;
            case "fileReplicate":
                FileReplicateRequestPayload fileReplicateRequestPayload = (FileReplicateRequestPayload) clientPayload;
                PeerInfo toBeReplicatedPeerInfo = fileReplicateRequestPayload.getToBeReplicatedPeer();
                String plainTextFileName = fileReplicateRequestPayload.getFileName();
                Optional<String> encryptedFileName = FileOperations.getEncryptedFileNameIfPresentInStorageBucket(peerEncryptedFilesPath, plainTextFileName, peerLocalSecretKey);

                if (encryptedFileName.isPresent()) {
                    String absoluteEncryptedFileName = Paths.get(peerEncryptedFilesPath, encryptedFileName.get()).toString();
                    String fileContents = FileOperations.getPlainTextFromEncryptedFile(absoluteEncryptedFileName, peerLocalSecretKey);
                    updateFilePayload = new UpdateFilePayload.Builder()
                        .setCommand(Commands.touch.name())
                        // TODO: update value of port_no later
                        .setPeerInfo(new PeerInfo(PEER_ID, -1))
                        .setFileName(plainTextFileName)
                        .setFileContents(fileContents)
                        .build();

                    ExecutorService executor = Executors.newSingleThreadExecutor();
                    Future<ResponsePayload> future = executor.submit(new PeerRequester(peerInfo, toBeReplicatedPeerInfo, updateFilePayload));
                    executor.shutdown();
                    statusCode = 200;
                    message = String.format("%s: `%s` replicated successfully", PEER_ID, plainTextFileName);
                } else {
                    statusCode = 400;
                    message = String.format("%s: `%s` replication failed. File was not found at %s", PEER_ID, plainTextFileName, peer_id);
                }

                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(statusCode)
                    .setMessage(message)
                    .build();
                break;
            default:
                responsePayload = new ResponsePayload.Builder()
                    .setStatusCode(400)
                    .setMessage(String.format("%s: Command handler not found for %s", PEER_ID, command))
                    .build();
                System.out.println(ANSI_YELLOW + String.format("Invalid command issued: %s", command) + ANSI_RESET);
        }

        return responsePayload;
    }
}
