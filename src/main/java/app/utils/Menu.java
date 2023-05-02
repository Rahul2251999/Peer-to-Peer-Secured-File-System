package app.peer;

import app.FileWatcher;
import app.Models.Payloads.*;
import app.Models.Payloads.DeleteFileResponsePayload;
import app.Models.Payloads.Peer.ListFilesResponsePayload;
import app.Models.Payloads.Peer.ReadFilePayload;
import app.Models.Payloads.Peer.ReadFileResponsePayload;
import app.Models.Payloads.Peer.UpdateFilePayload;
import app.Models.PeerInfo;
import app.TextEditor;
import app.constants.Commands;
import app.constants.Constants;
import app.utils.*;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static app.constants.Constants.TerminalColors.*;

public class Menu implements Runnable {
    private static Socket FDSSocket = null;
    private static Socket CASocket = null;
    private PeerInfo peerInfo;
    private SecretKey peerSecretKey;
    private SecretKey peerLocalSecretKey;
    private Properties properties;

    public Menu(PeerInfo peerInfo, SecretKey peerSecretKey, SecretKey peerLocalSecretKey, Properties properties) {
        this.peerInfo = peerInfo;
        this.peerSecretKey = peerSecretKey;
        this.peerLocalSecretKey = peerLocalSecretKey;
        this.properties = properties;
    }

    public static void showMenu() {
        System.out.println(ANSI_YELLOW + "\n//////////////////////////////////");
        System.out.println("keygen --keyLength");
        System.out.println("mkdir --directoryName --accessList");
        System.out.println("touch --fileName --accessList");
        System.out.println("chmod --[directoryName|fileName] --updatedAccessList");
        System.out.println("cd --directoryName");
        System.out.println("rm --fileName");
        System.out.println("restore --fileName");
        System.out.println("ls");
        System.out.println("//////////////////////////////////" + ANSI_RESET);
    }

    @Override
    public void run() {
        try {
            FDSSocket = new Socket(properties.getProperty("IP_ADDRESS"), Integer.parseInt(properties.getProperty("FDS_PORT")));
            System.out.println(ANSI_BLUE + "Connected to File Distribution Server" + ANSI_RESET);
            CASocket = new Socket(properties.getProperty("IP_ADDRESS"), Integer.parseInt(properties.getProperty("CA_PORT")));
            System.out.println(ANSI_BLUE + "Connected to Certificate Authority\n" + ANSI_RESET);

            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            ObjectOutputStream FDSWriter = new ObjectOutputStream(FDSSocket.getOutputStream());
            ObjectInputStream FDSReader = new ObjectInputStream(FDSSocket.getInputStream());
            ObjectOutputStream CAWriter = new ObjectOutputStream(CASocket.getOutputStream());
            ObjectInputStream CAReader = new ObjectInputStream(CASocket.getInputStream());

            String peerStorageBucketPath = "./src/main/resources/" + peerInfo.getPeer_id();
            String peerEncryptedFilesPath = Constants.FilePaths.peerEncryptedFilesPath.replace("{peerId}", peerInfo.getPeer_id());

            byte[] FDSPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("FDS_PBK"));

            Payload payload = new InitPayload.Builder()
                .setCommand(Commands.registerPeer.name())
                .setPeerInfo(peerInfo)
                .setKey(RSA.encrypt(peerSecretKey.getEncoded(), RSA.getPublicKey(FDSPublicKeyBytes)))
                .build();

            writeToServerAndReadResponse(FDSReader, FDSWriter, payload);

            byte[] CAPublicKeyBytes = Base64.getDecoder().decode(properties.getProperty("CA_PBK"));
            payload = new InitPayload.Builder()
                .setCommand(Commands.registerPeer.name())
                .setPeerInfo(peerInfo)
                .setKey(RSA.encrypt(peerSecretKey.getEncoded(), RSA.getPublicKey(CAPublicKeyBytes)))
                .build();

            writeToServerAndReadResponse(CAReader, CAWriter, payload);

            ResponsePayload responsePayload;
            String userInput;
            String pwd = "/";

            while (true) {
                System.out.print(peerInfo.getPeer_id() + " " + pwd + " > ");
                userInput = consoleReader.readLine();
                if (userInput == null || userInput.equalsIgnoreCase("exit")) {
                    break;
                }

                String[] command = userInput.split(" ", 2);
                String commandName = command[0];
                if (commandName.matches("^keygen.*")) {
                    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                    SecureRandom secureRandom = new SecureRandom();
                    keyGen.init(256, secureRandom);
                    peerSecretKey = keyGen.generateKey();

                    AES.writeKeyToFile(peerSecretKey, peerStorageBucketPath + "/keys/key.der");

                    payload = new InitPayload.Builder()
                        .setPeerInfo(peerInfo)
                        .setCommand(Commands.registerKey.name())
                        .setKey(RSA.encrypt(peerSecretKey.getEncoded(), RSA.getPublicKey(CAPublicKeyBytes)))
                        .build();
                    writeToServerAndReadResponse(CAReader, CAWriter, payload);

                    payload = new InitPayload.Builder()
                        .setPeerInfo(peerInfo)
                        .setCommand(Commands.registerKey.name())
                        .setKey(RSA.encrypt(peerSecretKey.getEncoded(), RSA.getPublicKey(FDSPublicKeyBytes)))
                        .build();
                    writeToServerAndReadResponse(FDSReader, FDSWriter, payload);
                } else if (commandName.matches("^mkdir.*")) {
                    if (command[1] == null) {
                        System.out.println(ANSI_RED + "Invalid command-line arguments" + ANSI_RESET);
                        continue;
                    }

                    String[] commandArgs = command[1].split(" ");
                    String fileName = commandArgs[0];
                    Map<String, String> accessList = new HashMap<>();
                    for (int i=1; i<commandArgs.length - 1; i+=2) {
                        accessList.put(commandArgs[i], commandArgs[i + 1]);
                    }
                    payload = new CreateFilePayload.Builder()
                        .setCommand(Commands.mkdir.name())
                        .setFileName("/" + fileName)
                        .setParent(pwd)
                        .setAccessList(accessList)
                        .setPeerInfo(peerInfo)
                        .build();
                    EncryptedPayload encryptedPayload = new EncryptedPayload();
                    encryptedPayload.setData(AES.encrypt(peerSecretKey, CObject.objectToBytes(payload)));
                    encryptedPayload.setPeerInfo(peerInfo);
                    writeToServerAndReadResponse(FDSReader, FDSWriter, encryptedPayload);
                } else if (commandName.matches("^touch.*")) {
                    if (command[1] == null) {
                        System.out.println(ANSI_RED + "Invalid command-line arguments" + ANSI_RESET);
                        continue;
                    }

                    String[] commandArgs = command[1].split(" ");
                    String fileName = commandArgs[0];
                    Map<String, String> accessList = new HashMap<>();
                    for (int i=1; i<commandArgs.length - 1; i+=2) {
                        accessList.put(commandArgs[i], commandArgs[i + 1]);
                    }
                    payload = new CreateFilePayload.Builder()
                        .setCommand(Commands.touch.name())
                        .setFileName("/" + fileName)
                        .setParent(pwd)
                        .setAccessList(accessList)
                        .setPeerInfo(peerInfo)
                        .build();
                    EncryptedPayload encryptedPayload = new EncryptedPayload();
                    encryptedPayload.setData(AES.encrypt(peerSecretKey, CObject.objectToBytes(payload)));
                    encryptedPayload.setPeerInfo(peerInfo);

                    CreateFileResponsePayload createFileResponsePayload = (CreateFileResponsePayload) writeToServerAndReadResponse(FDSReader, FDSWriter, encryptedPayload);

                    if (Constants.HttpStatus.twoHundredClass.contains(createFileResponsePayload.getStatusCode()) ||
                        createFileResponsePayload.getStatusCode() == 409) {
                        Map<String, Integer> toBeReplicatedPeers = createFileResponsePayload.getToBeReplicatedPeers();

                        String absoluteFileName = Paths.get(((CreateFilePayload) payload).getParent(), ((CreateFilePayload) payload).getFileName()).toString();
                        String tempFilePath = Paths.get(peerStorageBucketPath, "temp.txt").toString();

                        Optional<String> encryptedFileName = FileOperations.getEncryptedFileNameIfPresentInStorageBucket(peerEncryptedFilesPath, absoluteFileName, peerLocalSecretKey);
                        String encryptedFileNamePath = null;

                        // if the file is present locally add event listener
                        // else create a new file and add event listener
                        if (encryptedFileName.isPresent()) {
                            encryptedFileNamePath = Paths.get(peerEncryptedFilesPath, encryptedFileName.get()).toString();
                        } else {
                            ExtractNameAndExtension extractNameAndExtension = new ExtractNameAndExtension(absoluteFileName);
                            extractNameAndExtension.run();

                            byte[] encryptedFileNameBytes = AES.encrypt(peerLocalSecretKey, extractNameAndExtension.getFileName().getBytes());
                            String encryptedAbsoluteFileName = Base64.getUrlEncoder().encodeToString(encryptedFileNameBytes) + "." + extractNameAndExtension.getExtension();

                            Path encryptedFilePath = Path.of(peerEncryptedFilesPath, encryptedAbsoluteFileName);
                            Files.createFile(encryptedFilePath);

                            encryptedFileNamePath = encryptedFilePath.toString();
                        }

                        // this listens to file changes and updates
                        // the temp.txt file used by TextEditor class as a buffer file
                        FileWatcher fileWatcher = new FileWatcher(Paths.get(encryptedFileNamePath), Paths.get(tempFilePath), peerLocalSecretKey);
                        Thread thread = new Thread(fileWatcher);
                        thread.start();

                        // File already exists in the network
                        if (createFileResponsePayload.getStatusCode() == 409) {
                            // check if it is replicated in the current peer,
                            // else get it from some other peer
                            // and add the data to temp.txt buffer file
                            if (toBeReplicatedPeers.containsKey(peerInfo.getPeer_id())) {
                                if (encryptedFileName.isPresent() && encryptedFileNamePath != null) {
                                    FileOperations.cloneEncryptedDataToPlainTextFile(encryptedFileNamePath, tempFilePath, peerLocalSecretKey);
                                }
                            } else {
                                List<String> keys = new ArrayList<>(toBeReplicatedPeers.keySet());
                                String randomPeerId = keys.get(new Random().nextInt(keys.size()));
                                int randomPeerPort = toBeReplicatedPeers.get(randomPeerId);

                                payload = new ReadFilePayload.Builder()
                                    .setCommand(Commands.read.name())
                                    .setPeerInfo(peerInfo)
                                    .setFileName(absoluteFileName)
                                    .build();

                                ExecutorService executor = Executors.newSingleThreadExecutor();
                                Future<ResponsePayload> future = executor.submit(new PeerRequester(peerInfo, new PeerInfo(randomPeerId, randomPeerPort), payload));
                                ReadFileResponsePayload readFileResponsePayload = (ReadFileResponsePayload) future.get();
                                String fileContent = readFileResponsePayload.readFileContent();
                                FileOperations.writeDataToPlainTextFile(fileContent, tempFilePath);
                                executor.shutdown();
                            }
                        }

                        TextEditor textEditor = new TextEditor(tempFilePath, createFileResponsePayload.isReadOnly(), absoluteFileName, toBeReplicatedPeers, peerInfo, peerEncryptedFilesPath, peerLocalSecretKey);
                        textEditor.start();

                        try {
                            textEditor.waitForClose();
                        } catch (InterruptedException e) {
                            System.out.println(ANSI_RED + "InterruptedException: " + e.getMessage() + ANSI_RESET);
                            e.printStackTrace();
                        }
                    }
                } else if (commandName.matches("^chmod.*")) {
                    String[] commandArgs = command[1].split(" ");
                    String fileName = commandArgs[0];
                    Map<String, String> accessList = new HashMap<>();
                    for (int i=1; i<commandArgs.length - 1; i+=2) {
                        accessList.put(commandArgs[i], commandArgs[i + 1]);
                    }
                    payload = new UpdatePermissionsPayload.Builder()
                        .setCommand(Commands.chmod.name())
                        .setPeerInfo(peerInfo)
                        .setAccessList(accessList)
                        .setParent(pwd)
                        .setFileName(fileName)
                        .build();

                    writeToServerAndReadResponse(FDSReader, FDSWriter, payload);
                } else if (commandName.matches("^ls.*")) {
                    payload = new ListFilesPayload.Builder()
                        .setCommand(Commands.ls.name())
                        .setPeerInfo(peerInfo)
                        .setPwd(pwd)
                        .build();
                    EncryptedPayload encryptedPayload = new EncryptedPayload();
                    encryptedPayload.setData(AES.encrypt(peerSecretKey, CObject.objectToBytes(payload)));
                    encryptedPayload.setPeerInfo(peerInfo);
                    ListFilesResponsePayload listFilesResponsePayload = (ListFilesResponsePayload) writeToServerAndReadResponse(FDSReader, FDSWriter, encryptedPayload);

                    if (Constants.HttpStatus.twoHundredClass.contains(listFilesResponsePayload.getStatusCode())) {
                        List<String> allLines = listFilesResponsePayload.getLines();

                        for (String line: allLines) {
                            System.out.println(line);
                        }
                    }
                } else if (commandName.matches("^cd.*")) {
                    if (command[1] == null) {
                        System.out.println(ANSI_RED + "Invalid command-line arguments" + ANSI_RESET);
                        continue;
                    }

                    String changeInto = command[1];

                    if (!changeInto.equals("..")) {
                        payload = new ChangeDirectoryPayload.Builder()
                            .setPwd(pwd)
                            .setChangeInto(changeInto)
                            .setPeerInfo(peerInfo)
                            .setCommand(Commands.cd.name())
                            .build();

                        EncryptedPayload encryptedPayload = new EncryptedPayload();
                        encryptedPayload.setData(AES.encrypt(peerSecretKey, CObject.objectToBytes(payload)));
                        encryptedPayload.setPeerInfo(peerInfo);

                        responsePayload = writeToServerAndReadResponse(FDSReader, FDSWriter, encryptedPayload);

                        if (Constants.HttpStatus.twoHundredClass.contains(responsePayload.getStatusCode())) {
                            pwd += "/" + changeInto;
                            pwd = Paths.get(pwd).normalize().toString();
                        }
                    } else {
                        int lastIndexOfSlash = pwd.lastIndexOf("/");
                        if (lastIndexOfSlash != -1) {
                            pwd = pwd.substring(0, lastIndexOfSlash);

                            if (pwd.equals("")) {
                                pwd = "/";
                            }
                        }
                    }
                } else if (userInput.matches("^rm .*")) {
                    String[] commandArgs = command[1].split(" ");
                    String fileName = commandArgs[0];
                    payload = new DeleteFilePayload.Builder()
                        .setCommand(Commands.rm.name())
                        .setPeerInfo(peerInfo)
                        .setParent(pwd)
                        .setFileName(fileName)
                        .build();

                    EncryptedPayload encryptedPayload = new EncryptedPayload();
                    encryptedPayload.setData(AES.encrypt(peerSecretKey, CObject.objectToBytes(payload)));
                    encryptedPayload.setPeerInfo(peerInfo);

                    responsePayload = writeToServerAndReadResponse(FDSReader, FDSWriter, encryptedPayload);
                    DeleteFileResponsePayload deleteFileResponsePayload = (DeleteFileResponsePayload) responsePayload;

                    if (Constants.HttpStatus.twoHundredClass.contains(responsePayload.getStatusCode())) {
                        Map<String, Integer> toBeDeletedPeers = deleteFileResponsePayload.getToBeDeletedPeers();

                        for(Map.Entry<String, Integer> peer: toBeDeletedPeers.entrySet()) {
                            PeerInfo toBeDeletedPeerInfo = new PeerInfo(peer.getKey(), peer.getValue());

                            ExecutorService executor = Executors.newSingleThreadExecutor();
                            Future<ResponsePayload> future = executor.submit(new PeerRequester(peerInfo, toBeDeletedPeerInfo, payload));
                            executor.shutdown();
                        }
                    }
                } else if (commandName.matches("^restore.*")) {
                    String[] commandArgs = command[1].split(" ");
                    String fileName = commandArgs[0];
                    payload = new RestoreFilePayload.Builder()
                        .setCommand(Commands.restore.name())
                        .setPeerInfo(peerInfo)
                        .setParent(pwd)
                        .setFileName(fileName)
                        .build();

                    responsePayload = writeToServerAndReadResponse(FDSReader, FDSWriter, payload);
                    RestoreFileResponsePayload  restoreFileResponsePayload = (RestoreFileResponsePayload) responsePayload;

                    if (Constants.HttpStatus.twoHundredClass.contains(restoreFileResponsePayload.getStatusCode())) {
                        Map<String, Integer> toBeReplicatedPeers = restoreFileResponsePayload.getToBeReplicatedPeers();

                        String absoluteFileName = Paths.get(((RestoreFilePayload) payload).getParent(), ((RestoreFilePayload) payload).getFileName()).toString();
                        Optional<String> encryptedFileName = FileOperations.getEncryptedFileNameIfPresentInStorageBucket(peerEncryptedFilesPath, absoluteFileName, peerLocalSecretKey);

                        if (encryptedFileName.isPresent()) {
                            String absoluteEncryptedFileName = Paths.get(peerEncryptedFilesPath, encryptedFileName.get()).toString();
                            String fileContents = FileOperations.getPlainTextFromEncryptedFile(absoluteEncryptedFileName, peerLocalSecretKey);
                            UpdateFilePayload updateFilePayload = new UpdateFilePayload.Builder()
                                .setCommand(Commands.restore.name())
                                .setPeerInfo(peerInfo)
                                .setFileName(absoluteFileName)
                                .setFileContents(fileContents)
                                .build();

                            for (Map.Entry<String, Integer> peer : toBeReplicatedPeers.entrySet()) {
                                PeerInfo toBeReplicatedPeerInfo = new PeerInfo(peer.getKey(), peer.getValue());

                                ExecutorService executor = Executors.newSingleThreadExecutor();
                                Future<ResponsePayload> future = executor.submit(new PeerRequester(peerInfo, toBeReplicatedPeerInfo, updateFilePayload));
                                executor.shutdown();
                            }
                        } else {
                            System.out.println(ANSI_RED + "REPLICATION_ERROR: File not found" + ANSI_RESET);
                        }
                    }
                } else {
                    System.out.println(ANSI_YELLOW + "Unrecognized Command" + ANSI_RESET);
                    showMenu();
                }
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (NoSuchAlgorithmException | IllegalBlockSizeException | InvalidKeySpecException |
                 NoSuchPaddingException | BadPaddingException | InvalidKeyException | ClassNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } finally {
            try {
                if (FDSSocket != null) {
                    FDSSocket.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "IOException: Error closing socket: " + e.getMessage() + ANSI_RESET);
                e.printStackTrace();
            }
        }
    }

    public static ResponsePayload writeToServerAndReadResponse(ObjectInputStream reader, ObjectOutputStream writer, Object payload) throws IOException, ClassNotFoundException {
        writer.writeObject(payload);
        writer.flush();

        ResponsePayload responsePayload = (ResponsePayload) reader.readObject();

        if (Constants.HttpStatus.fourHundredClass.contains(responsePayload.getStatusCode())) {
            System.out.println(ANSI_RED + responsePayload.getMessage() + ANSI_RESET);
        } else if (Constants.HttpStatus.twoHundredClass.contains(responsePayload.getStatusCode()) && !responsePayload.getMessage().equals("")) {
            System.out.println(ANSI_GREEN + responsePayload.getMessage() + ANSI_RESET);
        }

        return responsePayload;
    }
}
