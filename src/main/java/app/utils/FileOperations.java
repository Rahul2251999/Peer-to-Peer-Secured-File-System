package app.utils;

import app.Models.Payloads.Peer.ReadFilePayload;
import app.Models.Payloads.Peer.ReadFileResponsePayload;
import app.Models.Payloads.Peer.UpdateFilePayload;
import app.Models.Payloads.ResponsePayload;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static app.constants.Constants.TerminalColors.ANSI_RED;
import static app.constants.Constants.TerminalColors.ANSI_RESET;

public class FileOperations {
    public static ResponsePayload touch(UpdateFilePayload updateFilePayload, String peerId, SecretKey peerLocalSecretKey, String peerEncryptedFilesPath) throws Exception {
        ExtractNameAndExtension extractNameAndExtension = new ExtractNameAndExtension(updateFilePayload.getFileName());
        extractNameAndExtension.run();

        byte[] encryptedContent = AES.encrypt(peerLocalSecretKey, updateFilePayload.getFileContents().getBytes());

        Optional<String> encryptedFileName = getEncryptedFileNameIfPresentInStorageBucket(peerEncryptedFilesPath, updateFilePayload.getFileName(), peerLocalSecretKey);
        String encryptedAbsoluteFileName, message;
        int statusCode;
        if (encryptedFileName.isPresent()) {
            encryptedAbsoluteFileName = encryptedFileName.get();
            statusCode = 200;
            message = String.format("%s: ACK: %s updated", peerId, updateFilePayload.getFileName());
        } else {
            byte[] encryptedFileNameBytes = AES.encrypt(peerLocalSecretKey, extractNameAndExtension.getFileName().getBytes());
            encryptedAbsoluteFileName = Base64.getUrlEncoder().encodeToString(encryptedFileNameBytes) + "." + extractNameAndExtension.getExtension();
            statusCode = 201;
            message = String.format("%s: ACK: %s created", peerId, updateFilePayload.getFileName());
        }

        Path path = Paths.get(peerEncryptedFilesPath, encryptedAbsoluteFileName);
        Files.write(path, encryptedContent, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

        return new ResponsePayload.Builder()
            .setStatusCode(statusCode)
            .setMessage(message)
            .build();
    }

    public static ReadFileResponsePayload read(ReadFilePayload readFilePayload, SecretKey peerLocalSecretKey, String peerEncryptedFilesPath) throws Exception {
        Optional<String> encryptedFileName = getEncryptedFileNameIfPresentInStorageBucket(peerEncryptedFilesPath, readFilePayload.getFileName(), peerLocalSecretKey);
        String message, fileContent = null;
        int statusCode;
        if (encryptedFileName.isPresent()) {
            Path absoluteFileNamePath = Paths.get(peerEncryptedFilesPath, encryptedFileName.get());

            byte[] encryptedBytes = Files.readAllBytes(absoluteFileNamePath);

            byte[] decryptedBytes = AES.decrypt(peerLocalSecretKey, encryptedBytes);
            fileContent = new String(decryptedBytes);
            statusCode = 200;
            message = String.format("");
        } else {
            statusCode = 400;
            message = String.format("`%s` not found", readFilePayload.getFileName());
        }

        return new ReadFileResponsePayload.Builder()
            .setMessage(message)
            .setStatusCode(statusCode)
            .setFileContent(fileContent)
            .build();
    }

    public static ResponsePayload delete(String fileName, String peerId, SecretKey peerLocalSecretKey, String peerEncryptedFilesPath) throws Exception {
        Optional<String> encryptedFileName = getEncryptedFileNameIfPresentInStorageBucket(peerEncryptedFilesPath, fileName, peerLocalSecretKey);
        String message;
        int statusCode;
        if (encryptedFileName.isPresent()) {
            Path absoluteFileNamePath = Paths.get(peerEncryptedFilesPath, encryptedFileName.get());
            File file = new File(absoluteFileNamePath.toString());

            if (file.delete()) {
                message = String.format("%s: ACK: `%s` deleted successfully", peerId, fileName);
                statusCode = 200;
            } else {
                message = String.format("%s: %s deleted failed", peerId, fileName);
                statusCode = 400;
            }
        } else {
            message = String.format("%s: %s file not found", peerId, fileName);
            statusCode = 404;
        }

        return new ResponsePayload.Builder()
            .setMessage(message)
            .setStatusCode(statusCode)
            .build();
    }

    public static boolean delete(String plainTextFileName, String peerEncryptedFilesPath) {
        Path absoluteFileNamePath = Paths.get(peerEncryptedFilesPath, plainTextFileName);
        File file = new File(absoluteFileNamePath.toString());

        if (file.delete()) {
            return true;
        } else {
            return false;
        }
    }

    public static Optional<String> getEncryptedFileNameIfPresentInStorageBucket(String peerEncryptedFilesPath, String plainTextFileName, SecretKey peerLocalSecretKey) throws IOException {
        Path path = Paths.get(peerEncryptedFilesPath);

        return Files.list(path)
            .filter(Files::isRegularFile)
            .map(filePath -> filePath.getFileName().toString())
            .filter(encryptedFileName -> {
                try {
                    String absoluteFileName = getPlainTextPathFromEncryptedPath(encryptedFileName, peerLocalSecretKey);
                    return absoluteFileName.equals(plainTextFileName);
                } catch (Exception e) {
                    System.err.println("An error occurred while decrypting file: " + e.getMessage());
                    e.printStackTrace();
                    return false;
                }
            })
            .findFirst();
    }

    private static String getPlainTextPathFromEncryptedPath(String encryptedPath, SecretKey peerLocalSecretKey) {
        String absoluteFileName = null;
        try {
            ExtractNameAndExtension extractNameAndExtension = new ExtractNameAndExtension(encryptedPath);
            extractNameAndExtension.run();

            byte[] encryptedFileNameBytes = Base64.getUrlDecoder().decode(extractNameAndExtension.getFileName());

            byte[] decryptedFileNameBytes = AES.decrypt(peerLocalSecretKey, encryptedFileNameBytes);
            String decryptedFileName = new String(decryptedFileNameBytes, StandardCharsets.UTF_8);
            absoluteFileName = decryptedFileName + "." + extractNameAndExtension.getExtension();
        } catch (Exception e) {
//            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
//            e.printStackTrace();
            return encryptedPath;
        }
        return absoluteFileName;
    }

    public static void cloneEncryptedDataToPlainTextFile(String encryptedFilePath, String plainTextFilePath, SecretKey key) throws Exception {
        byte[] encryptedBytes = Files.readAllBytes(Paths.get(encryptedFilePath));

        byte[] decryptedBytes = AES.decrypt(key, encryptedBytes);

        try (FileOutputStream fos = new FileOutputStream(plainTextFilePath)) {
            fos.write(decryptedBytes);
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    public static String getPlainTextFromEncryptedFile(String encryptedFilePath, SecretKey key) throws Exception {
        byte[] encryptedBytes = Files.readAllBytes(Paths.get(encryptedFilePath));

        if (encryptedBytes != null && encryptedBytes.length > 0) {
            byte[] decryptedBytes = AES.decrypt(key, encryptedBytes);

            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } else {
            return new String("".getBytes(), StandardCharsets.UTF_8);
        }
    }

    public static void writeDataToPlainTextFile(String data, String plainTextFilePath) {
        try {
            FileWriter writer = new FileWriter(plainTextFilePath);

            writer.write(data);

            writer.close();
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
            e.printStackTrace();
        }
    }

    public static Set<String> getPlainTextPaths(String encryptedFilesPath, SecretKey peerLocalSecretKey) {
        Set<String> plainTextPaths = new HashSet<>();

        File directory = new File(encryptedFilesPath);
        File[] files = directory.listFiles();
        for (File file: files) {
            String encryptedFileName = file.getName();
            String plainTextPath = getPlainTextPathFromEncryptedPath(encryptedFileName, peerLocalSecretKey);
            plainTextPaths.add(plainTextPath);
        }

        return plainTextPaths;
    }
}
