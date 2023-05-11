package app.FDS;

import app.Models.Payloads.FileListingPayload;
import app.Models.Payloads.FileListingResponsePayload;
import app.Models.Payloads.FileReplicateRequestPayload;
import app.Models.Payloads.ResponsePayload;
import app.Models.PeerDB;
import app.Models.PeerInfo;
import app.MongoConnectionManager;
import app.constants.Commands;
import app.constants.Constants;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoCursor;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Aggregates;
import com.mongodb.client.model.Projections;
import org.bson.Document;
import org.bson.conversions.Bson;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.file.Paths;
import java.util.*;

import static app.constants.Constants.TerminalColors.*;

public class MaliciousActivityDetector implements Runnable {
    private Properties properties;

    public MaliciousActivityDetector(Properties properties) {
        this.properties = properties;
    }

    @Override
    public void run() {
        MongoDatabase db = MongoConnectionManager.getDatabase();

        while (true) {
            try {
                Thread.sleep(30000);
                MongoCollection<Document> collection = db.getCollection("file_metadata");

                try {
                    String peerDBMapFile = Paths.get(Constants.FilePaths.FDSStorageBucket, "peerDBMap.dat").toString();
                    FileInputStream fis = new FileInputStream(peerDBMapFile);
                    ObjectInputStream ois = new ObjectInputStream(fis);
                    Map<String, PeerDB> peerDBMap = (Map<String, PeerDB>) ois.readObject();
                    ois.close();
                    fis.close();

                    for (Map.Entry<String, PeerDB> peerDBEntry: peerDBMap.entrySet()) {
                        if (peerDBEntry.getValue().isActive()) {
                            String peerId = peerDBEntry.getKey();
                            PeerDB peerDB = peerDBEntry.getValue();
                            Set<String> absoluteFilePaths = new HashSet<>();

                            Document query = new Document("replicatedPeers", new Document("$elemMatch", new Document("$eq", peerId)));
                            query.append("isDirectory", false);
                            query.append("isDeleted", false);
                            List<Bson> pipeline = Arrays.asList(
                                Aggregates.match(query),
                                Aggregates.project(Projections.fields(
                                    Projections.computed("absoluteFilePath", new Document("$concat", Arrays.asList("$parent", "$name")))
                                ))
                            );
                            MongoCursor<Document> cursor = collection.aggregate(pipeline).iterator();

                            while (cursor.hasNext()) {
                                Document document = cursor.next();
                                String absoluteFilePath = document.getString("absoluteFilePath");
                                absoluteFilePaths.add(absoluteFilePath);
                            }

                            PeerInfo peerInfo = new PeerInfo("FDS", Integer.parseInt(properties.getProperty("FDS_PORT")));
                            FileListingPayload fileListingPayload = new FileListingPayload.Builder()
                                .setCommand(Commands.fileListing.name())
                                .setPeerInfo(peerInfo)
                                .setFiles(absoluteFilePaths)
                                .build();

                            Socket peerSocket = new Socket(properties.getProperty("IP_ADDRESS"), peerDB.getPort_no());
                            System.out.println(ANSI_BLUE + String.format("Checking for Malicious Activity in Peer: %s", peerDB.getPeer_id()) + ANSI_RESET);

                            ObjectOutputStream peerWriter = new ObjectOutputStream(peerSocket.getOutputStream());
                            ObjectInputStream peerReader = new ObjectInputStream(peerSocket.getInputStream());

                            peerWriter.writeObject(fileListingPayload);
                            peerWriter.flush();

                            FileListingResponsePayload fileListingResponsePayload = (FileListingResponsePayload) peerReader.readObject();

                            if (Constants.HttpStatus.fourHundredClass.contains(fileListingResponsePayload.getStatusCode())) {
                                Set<String> unTraceableFiles = fileListingResponsePayload.getUnTraceableFiles();
                                for (String file: unTraceableFiles) {
                                    query = new Document("$expr", new Document("$eq", Arrays.asList(new Document("$concat", Arrays.asList("$parent", "$name")), file)));
                                    Document document = collection.find(query).first();

                                    ArrayList<String> replicatedPeerIds = (ArrayList<String>) document.get("replicatedPeers");

                                    for (String replicatedPeerId: replicatedPeerIds) {
                                        if (!replicatedPeerId.equals(peerId)) {
                                            PeerInfo replicatedPeerInfo = peerDBMap.get(replicatedPeerId);
                                            System.out.println(ANSI_RED + String.format("`%s` not found", file) + ANSI_RESET);
                                            System.out.println(ANSI_BLUE + String.format("Trying to replicate `%s` from %s to %s", file, replicatedPeerId, peerDB.getPeer_id()) + ANSI_RESET);

                                            PeerInfo toBeReplicatedPeer = new PeerInfo(peerDB.getPeer_id(), peerDB.getPort_no());
                                            Socket ownerPeerSocket = new Socket(properties.getProperty("IP_ADDRESS"), replicatedPeerInfo.getPort_no());
                                            ObjectOutputStream ownerPeerWriter = new ObjectOutputStream(ownerPeerSocket.getOutputStream());
                                            ObjectInputStream ownerPeerReader = new ObjectInputStream(ownerPeerSocket.getInputStream());

                                            FileReplicateRequestPayload fileReplicateRequestPayload = new FileReplicateRequestPayload.Builder()
                                                .setCommand(Commands.fileReplicate.name())
                                                .setPeerInfo(peerInfo)
                                                .setFileName(file)
                                                .setToBeReplicatedPeer(toBeReplicatedPeer)
                                                .build();

                                            ownerPeerWriter.writeObject(fileReplicateRequestPayload);
                                            ownerPeerWriter.flush();

                                            ResponsePayload responsePayload = (ResponsePayload) ownerPeerReader.readObject();

                                            // if the replication is successful close, else try bruteforce for other peers
                                            if (Constants.HttpStatus.twoHundredClass.contains(responsePayload.getStatusCode())) {
                                                System.out.println(ANSI_BLUE + String.format("Replicating `%s` on %s successfully", file, peerDB.getPeer_id()) + ANSI_RESET);
                                                break;
                                            } else {
                                                System.out.println(ANSI_RED + responsePayload.getMessage() + ANSI_RESET);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (IOException | ClassNotFoundException e) {
                    e.printStackTrace();
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
