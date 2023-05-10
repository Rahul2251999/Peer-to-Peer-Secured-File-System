package app;

import app.Models.Payloads.Peer.UpdateFilePayload;
import app.Models.Payloads.ResponsePayload;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.peer.PeerRequester;
import app.utils.FileOperations;

import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.*;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.*;

import static app.constants.Constants.TerminalColors.ANSI_RED;
import static app.constants.Constants.TerminalColors.ANSI_RESET;

public class TextEditor {
    private File initialFile;
    private String absoluteFileName;
    private Map<String, Integer> toBeReplicatedPeers = null;
    private PeerInfo peerInfo;
    private boolean skipSave = false;
    private CountDownLatch closeLatch;
    private FileWatcher fileWatcher;
    private String peerEncryptedFilesPath;
    private SecretKey peerLocalSecretKey;
    private boolean readOnly;

    public TextEditor(String temporaryFileName, boolean readOnly, String absoluteFileName, Map<String, Integer> toBeReplicatedPeers, PeerInfo peerInfo, String peerEncryptedFilesPath, SecretKey peerLocalSecretKey) {
        this.initialFile = new File(temporaryFileName);
        this.absoluteFileName = absoluteFileName;
        this.toBeReplicatedPeers = toBeReplicatedPeers;
        this.peerInfo = peerInfo;
        this.closeLatch = new CountDownLatch(1);
        this.peerEncryptedFilesPath = peerEncryptedFilesPath;
        this.peerLocalSecretKey = peerLocalSecretKey;
        this.readOnly = readOnly;
    }

    private static final int SAVE_DELAY = 300; // Save file after .3 seconds of inactivity

    public void start() {
        JTextArea textArea = new JTextArea(30, 80);

        textArea.setEditable(!this.readOnly);

        fileWatcher = new FileWatcher(textArea, initialFile.toPath());
        fileWatcher.execute();

        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame(String.format("%s - %s %s", this.peerInfo.getPeer_id(), absoluteFileName, (readOnly ? "(read-only)": "")));
            JScrollPane scrollPane = new JScrollPane(textArea);

            if (initialFile.exists() && initialFile.isFile()) {
                openFile(textArea, initialFile);
            }

            if (!readOnly) {
                Timer saveTimer = new Timer();

                textArea.addKeyListener(new KeyAdapter() {
                    TimerTask saveTask;

                    @Override
                    public void keyTyped(KeyEvent e) {
                        scheduleSave();
                    }

                    @Override
                    public void keyPressed(KeyEvent e) {
                        scheduleSave();
                    }

                    @Override
                    public void keyReleased(KeyEvent e) {
                        scheduleSave();
                    }

                    private void scheduleSave() {
                        if (skipSave) {
                            return;
                        }
                        if (saveTask != null) {
                            saveTask.cancel();
                        }
                        saveTask = new TimerTask() {
                            @Override
                            public void run() {
                            saveToFile(textArea, initialFile);
                            UpdateFilePayload updateFilePayload = new UpdateFilePayload.Builder()
                                .setCommand(Commands.touch.name())
                                .setPeerInfo(peerInfo)
                                .setFileName(absoluteFileName)
                                .setFileContents(textArea.getText())
                                .build();

                            for (Map.Entry<String, Integer> peer : toBeReplicatedPeers.entrySet()) {
                                PeerInfo requestingPeerInfo = new PeerInfo(peer.getKey(), peer.getValue());
                                try {
                                    if (requestingPeerInfo.getPeer_id().equals(peerInfo.getPeer_id())) {
                                        FileOperations.touch(updateFilePayload, peerInfo.getPeer_id(), peerLocalSecretKey, peerEncryptedFilesPath);
                                    } else {
                                        ExecutorService executor = Executors.newSingleThreadExecutor();
                                        Future<ResponsePayload> future = executor.submit(new PeerRequester(peerInfo, requestingPeerInfo, updateFilePayload));
                                        executor.shutdown();
                                    }
                                } catch (IOException e) {
                                    System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
                                    e.printStackTrace();
                                } catch (Exception e) {
                                    System.out.println(ANSI_RED + "Exception: " + e.getMessage() + ANSI_RESET);
                                    e.printStackTrace();
                                }
                            }
                            }
                        };
                        saveTimer.schedule(saveTask, SAVE_DELAY);
                    }
                });
            }

            // Add custom key bindings
            InputMap inputMap = textArea.getInputMap(JComponent.WHEN_FOCUSED);
            ActionMap actionMap = textArea.getActionMap();

            // Bind left arrow key
            KeyStroke left = KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, 0);
            inputMap.put(left, "left");
            actionMap.put("left", new CursorAction(textArea, "left"));

            // Bind right arrow key
            KeyStroke right = KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, 0);
            inputMap.put(right, "right");
            actionMap.put("right", new CursorAction(textArea, "right"));

            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            frame.addWindowListener(new WindowAdapter() {
                @Override
                public void windowClosed(WindowEvent e) {
                    super.windowClosed(e);
                    if (initialFile != null && initialFile.exists()) {
                        initialFile.delete();
                    }
                    closeLatch.countDown();
                }
            });
            frame.getContentPane().add(scrollPane, BorderLayout.CENTER);
            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);

        });
    }

    static class CursorAction extends AbstractAction {
        JTextArea textArea;
        String direction;

        CursorAction(JTextArea textArea, String direction) {
            this.textArea = textArea;
            this.direction = direction;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            int currentPosition = textArea.getCaretPosition();
            int newPosition = -1;

            switch (direction) {
                case "left":
                    newPosition = Math.max(0, currentPosition - 1);
                    break;
                case "right":
                    newPosition = Math.min(textArea.getDocument().getLength(), currentPosition + 1);
                    break;
            }

            if (newPosition != -1) {
                textArea.setCaretPosition(newPosition);
            }
        }
    }

    private static void openFile(JTextArea textArea, File file) {
        int caretPosition = textArea.getCaretPosition();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            textArea.read(reader, null);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "An error occurred while opening the file.", "Error", JOptionPane.ERROR_MESSAGE);
        }
        textArea.setCaretPosition(Math.min(caretPosition, textArea.getDocument().getLength()));
    }

    private void saveToFile(JTextArea textArea, File file) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            textArea.write(writer);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "An error occurred while saving the file.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    public void waitForClose() throws InterruptedException {
        closeLatch.await();
        fileWatcher.cancel(false);
    }

    class FileWatcher extends SwingWorker<Void, Void> {
        private JTextArea textArea;
        private Path path;

        public FileWatcher(JTextArea textArea, Path path) {
            this.textArea = textArea;
            this.path = path;
        }

        @Override
        protected Void doInBackground() throws Exception {
            watchFileChanges();
            return null;
        }

        private void watchFileChanges() throws IOException {
            WatchService watchService = FileSystems.getDefault().newWatchService();
            path.toAbsolutePath().getParent().register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

            while (!isCancelled()) {
                WatchKey key;
                try {
                    key = watchService.poll(100, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    break;
                }

                if (key != null) {
                    for (WatchEvent<?> event : key.pollEvents()) {
                        if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                            continue;
                        }

                        Path changedPath = (Path) event.context();
                        if (changedPath.toFile().getName().equals(path.toFile().getName())) {
                            SwingUtilities.invokeLater(() -> {
                                skipSave = true;
                                openFile(textArea, path.toFile());
                                skipSave = false;
                            });
                        }
                    }

                    boolean valid = key.reset();
                    if (!valid) {
                        break;
                    }
                }
            }
        }
    }
}
