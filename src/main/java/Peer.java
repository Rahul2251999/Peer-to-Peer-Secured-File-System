import java.net.*;
import java.io.*;

public class Peer {
    private static String IP_ADDRESS = "127.0.0.1";
    private static int FDS_PORT = 8080;
    private static String PEER_ID = null;
    private static Socket socket = null;

    public static void serverSocket (int PORT) throws IOException {

        try {
            ServerSocket serverSocket = new ServerSocket(PORT);

            Socket clientSocket = serverSocket.accept();

            ClientHandler clientHandler = new ClientHandler(clientSocket, PEER_ID);
            Thread thread = new Thread(clientHandler);
            thread.start();
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 2) {
            System.out.println("Incorrect number of arguments\n");
            System.exit(1);
        }

        PEER_ID = args[0];
        int PORT_NO = Integer.parseInt(args[1]);
        serverSocket(PORT_NO);

        try {
            socket = new Socket(IP_ADDRESS, FDS_PORT);
            System.out.println("Connected to server");

            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            DataInputStream serverReader = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream serverWriter = new DataOutputStream(socket.getOutputStream());

            String userInput;
            while (true) {
                System.out.print("> ");
                userInput = consoleReader.readLine();
                if (userInput == null || userInput.equalsIgnoreCase("exit")) {
                    break;
                } else if (userInput == "connect") {
                    Socket peerSocket = new Socket(IP_ADDRESS, 8002);
                    DataInputStream peerReader = new DataInputStream(new BufferedInputStream(peerSocket.getInputStream()));
                    DataOutputStream peerWriter = new DataOutputStream(peerSocket.getOutputStream());
                    peerWriter.writeUTF(userInput);
                    peerSocket.setSoTimeout(2000);
                    String peerResponse = peerReader.readUTF();
                    System.out.println(peerResponse);
                }
                serverWriter.writeUTF(userInput);
                serverWriter.flush();

                socket.setSoTimeout(2000);
                String serverResponse = serverReader.readUTF();
                System.out.println(serverResponse);
            }
        } catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (IOException e) {
                System.out.println("Error closing socket: " + e.getMessage());
            }
        }
    }
}

class ClientHandler implements Runnable {
    private Socket clientSocket;
    private String PEER_ID;
    private DataInputStream clientReader;
    private DataOutputStream clientWriter;

    public ClientHandler(Socket clientSocket, String PEER_ID) {
        this.clientSocket = clientSocket;
        this.PEER_ID = PEER_ID;
    }

    @Override
    public void run() {
        try {
            System.out.println("Thread started: " + Thread.currentThread());

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
        return PEER_ID + " ACK: " + input;
    }
}