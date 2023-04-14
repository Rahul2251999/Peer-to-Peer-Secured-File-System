package app;

import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoDatabase;

public class MongoConnectionManager {
    private static String DATABASE_NAME = null;
    private static String CONNECTION_STRING = null;

    private static MongoClient mongoClient;
    private static MongoDatabase database;

    public MongoConnectionManager(String connectionString, String databaseName) {
        CONNECTION_STRING = connectionString;
        DATABASE_NAME = databaseName;
    }

    public static MongoDatabase getDatabase() {
        if (database == null) {
            mongoClient = MongoClients.create(CONNECTION_STRING);
            database = mongoClient.getDatabase(DATABASE_NAME);
        }
        return database;
    }

    public static void close() {
        if (mongoClient != null) {
            mongoClient.close();
            mongoClient = null;
            database = null;
        }
    }
}
