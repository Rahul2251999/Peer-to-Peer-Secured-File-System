package app.utils;

public class ExtractNameAndExtension {
    // format: apple.txt
    private String absoluteFileName;
    // format: apple
    private String fileName;
    // format: txt
    private String extension;

    public ExtractNameAndExtension(String fileName) {
        this.absoluteFileName = fileName;
    }

    public String getFileName() {
        return fileName;
    }

    public String getExtension() {
        return extension;
    }

    public void run() {
        int lastDotIndex = this.absoluteFileName.lastIndexOf(".");

        if (lastDotIndex != -1) {
            this.fileName = absoluteFileName.substring(0, lastDotIndex);
            this.extension = absoluteFileName.substring(lastDotIndex + 1);
        } else {
            this.fileName = absoluteFileName;
            this.extension = "";
        }
    }
}
