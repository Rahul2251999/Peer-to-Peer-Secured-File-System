package app.Models.Payloads.Peer;

import app.Models.Payloads.CreateFileResponsePayload;

import java.io.Serializable;

public class CreateFilePayload implements Serializable {
    protected String fileName;

    public CreateFilePayload() {
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

}
