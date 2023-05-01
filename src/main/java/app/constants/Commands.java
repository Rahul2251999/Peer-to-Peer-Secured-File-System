package app.constants;

public enum Commands {
    // server actions
    registerPeer,
    registerKey,
    fetchKey,
    updatePeerKey,

    // file-system actions
    mkdir,
    touch,
    chmod,
    ls,
    cd,
    read,
    rm,
    restore,
    fileListing,
    fileReplicate
}
