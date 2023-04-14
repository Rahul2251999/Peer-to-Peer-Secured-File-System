package app.Models.Payloads;

import app.Models.PeerInfo;

import javax.crypto.*;
import java.io.*;
import java.security.*;

public class Payload implements Serializable {
    protected String command;
    protected PeerInfo peerInfo;

    protected Payload() {}

    protected Payload(Builder builder) {
        this.command = builder.command;
        this.peerInfo = builder.peerInfo;
    }

    public String getCommand() {
        return command;
    }

    public PeerInfo getPeerInfo() {
        return peerInfo;
    }

//    public byte[] encrypt(Key publicKey) throws Exception {
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        ObjectOutputStream oos = new ObjectOutputStream(baos);
//        oos.writeObject(this);
//        oos.flush();
//        oos.close();
//        byte[] plaintext = baos.toByteArray();
//
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] ciphertext = cipher.doFinal(plaintext);
//
//        return ciphertext;
//    }
//
//    public static Payload decrypt(byte[] ciphertext, Key privateKey) throws Exception {
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//        byte[] plaintext = cipher.doFinal(ciphertext);
//
//        ByteArrayInputStream bais = new ByteArrayInputStream(plaintext);
//        ObjectInputStream ois = new ObjectInputStream(bais);
//        Payload payload = (Payload) ois.readObject();
//        ois.close();
//
//        return payload;
//    }

    public byte[] encrypt(Key publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] plaintext = this.toByteArray();
        return cipher.doFinal(plaintext);
    }

    public static Payload decrypt(byte[] ciphertext, Key privateKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            ClassNotFoundException, IOException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plaintext = cipher.doFinal(ciphertext);
        return fromByteArray(plaintext);
    }

    // Convert Payload object to byte array
    public byte[] toByteArray() {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        try {
            ObjectOutputStream objOut = new ObjectOutputStream(byteOut);
            objOut.writeObject(this);
            objOut.flush();
            objOut.close();
            byteOut.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return byteOut.toByteArray();
    }

    // Convert byte array to Payload object
    public static Payload fromByteArray(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteIn = new ByteArrayInputStream(bytes);
        ObjectInputStream objIn = new ObjectInputStream(byteIn);
        Payload obj = (Payload) objIn.readObject();
        objIn.close();
        byteIn.close();
        return obj;
    }

    public static class Builder {
        private String command;
        private PeerInfo peerInfo;

        public Builder setCommand(String command) {
            this.command = command;
            return this;
        }

        public Builder setPeerInfo(PeerInfo peerInfo) {
            this.peerInfo = peerInfo;
            return this;
        }

        public Payload build() {
            return new Payload(this);
        }
    }
}
