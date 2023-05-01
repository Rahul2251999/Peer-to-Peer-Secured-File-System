package app.constants;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Constants {
    public class TerminalColors {
        public static final String ANSI_RESET = "\u001B[0m";
        public static final String ANSI_BLACK = "\u001B[30m";
        public static final String ANSI_RED = "\u001B[31m";
        public static final String ANSI_GREEN = "\u001B[32m";
        public static final String ANSI_YELLOW = "\u001B[33m";
        public static final String ANSI_BLUE = "\u001B[34m";
        public static final String ANSI_PURPLE = "\u001B[35m";
        public static final String ANSI_CYAN = "\u001B[36m";
        public static final String ANSI_WHITE = "\u001B[37m";
    }

    public class FilePaths {
        public static final String CAKeys = "src/main/resources/CA/keys";
        public static final String FDSStorageBucket = "src/main/resources/FDS";
        public static final String FDSKeys = "src/main/resources/FDS/keys";
        public static final String peerEncryptedFilesPath = "src/main/resources/{peerId}/files";
    }

    public class HttpStatus {
        public static final Set<Integer> twoHundredClass = new HashSet<>(Arrays.asList(200, 201));
        public static final Set<Integer> fourHundredClass = new HashSet<>(Arrays.asList(400, 401, 409, 404));
    }
}
