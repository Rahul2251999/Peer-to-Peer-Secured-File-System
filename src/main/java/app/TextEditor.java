package app;

import app.Models.Payloads.Payload;
import app.Models.Payloads.Peer.UpdateFilePayload;
import app.Models.PeerInfo;
import app.constants.Commands;
import app.peer.PeerRequester;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
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

import static app.constants.Constants.TerminalColors.ANSI_RED;
import static app.constants.Constants.TerminalColors.ANSI_RESET;

public class TextEditor {
    private File initialFile;
    private Map<String, Integer> toBeReplicatedPeers = null;
    private PeerInfo peerInfo;

    public TextEditor(String fileName, Map<String, Integer> toBeReplicatedPeers, PeerInfo peerInfo) {
        this.initialFile = new File(fileName);
        this.toBeReplicatedPeers = toBeReplicatedPeers;
        this.peerInfo = peerInfo;
    }

    private static final int SAVE_DELAY = 2000; // Save file after 2 seconds of inactivity

    public void start() {
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame(String.format("%s - %s", this.peerInfo.getPeer_id(), initialFile.getName()));
            JTextArea textArea = new JTextArea(30, 80);
            JScrollPane scrollPane = new JScrollPane(textArea);

            if (initialFile.exists() && initialFile.isFile()) {
                openFile(textArea, initialFile);
            }

            Timer saveTimer = new Timer();

            textArea.getDocument().addDocumentListener(new DocumentListener() {
                TimerTask saveTask;

                @Override
                public void insertUpdate(DocumentEvent e) {
                    scheduleSave();
                }

                @Override
                public void removeUpdate(DocumentEvent e) {
                    scheduleSave();
                }

                @Override
                public void changedUpdate(DocumentEvent e) {
                    scheduleSave();
                }

                private void scheduleSave() {
                    if (saveTask != null) {
                        saveTask.cancel();
                    }
                    saveTask = new TimerTask() {
                        @Override
                        public void run() {
                            saveToFile(textArea, initialFile);
                            Payload createFilePayload = new UpdateFilePayload.Builder()
                                .setCommand(Commands.touch.name())
                                .setPeerInfo(peerInfo)
                                .setFileName(initialFile.getName())
                                .setFileContents(textArea.getText())
                                .build();

                            for (Map.Entry<String, Integer> peer : toBeReplicatedPeers.entrySet()) {
                                PeerInfo requestingPeerInfo = new PeerInfo(peer.getKey(), peer.getValue());
                                try {
                                    PeerRequester peerRequester = new PeerRequester(peerInfo, requestingPeerInfo, createFilePayload);
                                    Thread thread = new Thread(peerRequester);
                                    thread.start();
                                } catch (IOException e) {
                                    System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
                                    e.printStackTrace();
                                }
                            }
                        }
                    };
                    saveTimer.schedule(saveTask, SAVE_DELAY);
                }
            });

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

            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.getContentPane().add(scrollPane, BorderLayout.CENTER);
            frame.pack();
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);

            // Monitor file changes
            new Thread(() -> {
                try {
                    watchFileChanges(textArea, initialFile.toPath());
                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
                }
            }).start();
        });
    }

    private void watchFileChanges(JTextArea textArea, Path path) throws IOException, InterruptedException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        path.toAbsolutePath().getParent().register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        while (true) {
            WatchKey key = watchService.take();
            for (WatchEvent<?> event : key.pollEvents()) {
                if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                    continue;
                }

                Path changedPath = (Path) event.context();
                if (changedPath.toFile().getName().equals(path.toFile().getName())) {
                    SwingUtilities.invokeLater(() -> {
                        openFile(textArea, initialFile);
                    });
                }
            }

            boolean valid = key.reset();
            if (!valid) {
                break;
            }
        }
    }

    private static String findChanges(String oldContent, String newContent) {
        int minLength = Math.min(oldContent.length(), newContent.length());
        int startIndex = -1;
        int endIndex = -1;

        for (int i = 0; i < minLength; i++) {
            if (oldContent.charAt(i) != newContent.charAt(i)) {
                startIndex = i;
                break;
            }
        }

        for (int i = 0; i < minLength; i++) {
            if (oldContent.charAt(oldContent.length() - 1 - i) != newContent.charAt(newContent.length() - 1 - i)) {
                endIndex = newContent.length() - i;
                break;
            }
        }

        if (startIndex == -1 || endIndex == -1) {
            return "";
        }

        return newContent.substring(startIndex, endIndex);
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
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            textArea.read(reader, null);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "An error occurred while opening the file.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveToFile(JTextArea textArea, File file) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            textArea.write(writer);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(null, "An error occurred while saving the file.", "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
