package app;

import app.utils.FileOperations;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.*;

public class FileWatcher implements Runnable {
    private Path sourceFile;
    private Path targetFile;
    private SecretKey secretKey;

    public FileWatcher(Path sourceFile, Path targetFile, SecretKey secretKey) {
        this.sourceFile = sourceFile;
        this.targetFile = targetFile;
        this.secretKey = secretKey;
    }

    @Override
    public void run() {
        try {
            startWatching();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void startWatching() throws IOException, InterruptedException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        sourceFile.getParent().register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        while (true) {
            WatchKey watchKey = watchService.take();

            for (WatchEvent<?> event : watchKey.pollEvents()) {
                if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
                    Path changedPath = (Path) event.context();
                    if (changedPath.equals(sourceFile.getFileName())) {
                        updateTargetFile();
                    }
                }
            }

            if (!watchKey.reset()) {
                break;
            }
        }
    }

    private void updateTargetFile() {
        try {
            String plainText = FileOperations.getPlainTextFromEncryptedFile(sourceFile.toString(), secretKey);
            FileOperations.writeDataToPlainTextFile(plainText, targetFile.toString());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
