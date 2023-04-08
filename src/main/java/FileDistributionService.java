import java.net.*;
import java.io.*;
import java.util.concurrent.TimeUnit;
import static com.constants.Constants.TerminalColors.*;

public class FileDistributionService {
    private static int PORT = 8080;
    private static ServerSocket serverSocket = null;

    public static void main(String[] args) {
        try {
            serverSocket = new ServerSocket(PORT);
            System.out.println(ANSI_BLUE + "Trying to start File Distribution Server on " + PORT + ANSI_RESET);
            TimeUnit.SECONDS.sleep(1);
            System.out.println(ANSI_BLUE + "Server started..." + ANSI_RESET);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println(ANSI_BLUE + "Client connected: " + clientSocket + ANSI_RESET);

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                Thread thread = new Thread(clientHandler);
                thread.start();
            }
        } catch (IOException e) {
            System.out.println(ANSI_RED + "IOException: " + e.getMessage() + ANSI_RESET);
        } catch (InterruptedException e) {
            System.out.println(ANSI_RED + "InterruptedException: " + e.getMessage() + ANSI_RESET);
        } finally {
            try {
                if (serverSocket != null) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                System.out.println(ANSI_RED + "InterruptedException: Error closing server socket: " + e.getMessage() + ANSI_RESET);
            }
        }
    }

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private DataInputStream clientReader;
        private DataOutputStream clientWriter;

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try {
                System.out.println(ANSI_BLUE + "Thread started: " + Thread.currentThread() + ANSI_RESET);

                clientReader = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
                clientWriter = new DataOutputStream(clientSocket.getOutputStream());

                String clientInput;
                while ((clientInput = clientReader.readUTF()) != null) {
                    String response = processInput(clientInput);
                    clientWriter.writeUTF(response);
                    clientWriter.flush();
                }
            } catch (IOException e) {
                System.out.println("Error: " + e.getMessage());
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
                    System.out.println("Error closing client socket: " + e.getMessage());
                }
            }
        }

        private String processInput(String input) {
            System.out.println(input);
            return "Server ACK: " + input;
        }
    }
}
