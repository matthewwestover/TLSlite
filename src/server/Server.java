package server;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;

public class Server {
    // These paths assume compiled in command line via
    // javac *.java in the server package folder
    // and java server.Server ran in the src folder
    private String serverCert = "./resources/certs/CASignedServerCertificate.pem";
    private String serverPrivateKey = "./resources/keys/serverPrivateKey.der";
    private String outputFile = "./resources/testServerOut.txt";
    private static int PORT = 8080;
    private Socket socket;
    private ServerSocket serverSocket;
    private Certificate signedServerCert;
    private PrivateKey rsaPrivate;
    private BigInteger dhPrivate;
    private BigInteger dhPublic;
    private byte[] signedKey;
    private byte[] nonce;
    private static SecretKeySpec serverEncrypt;
    private static SecretKeySpec clientEncrypt;
    private static SecretKeySpec serverMAC;
    private static SecretKeySpec clientMAC;
    private static IvParameterSpec serverIV;
    private static IvParameterSpec clientIV;

    public Server() {
        try {
            SecureRandom random = new SecureRandom();
            this.signedServerCert = Helpers.getCert(serverCert);
            this.rsaPrivate = Helpers.getRSAPrivKey(serverPrivateKey);
            this.dhPrivate = new BigInteger(Integer.toString(random.nextInt()));
            this.dhPublic = Helpers.getDHKey(dhPrivate);
            this.signedKey = Helpers.getSignedKey(rsaPrivate, dhPublic);
            this.serverSocket = new ServerSocket(PORT);
            this.socket = serverSocket.accept();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Server initialization error: " + e.getMessage());
        }
    }

    public static void makeSecretKeys(byte[] nonce, BigInteger sharedSecret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] sharedSecretBytes = sharedSecret.toByteArray();
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(nonce, "HmacSHA256");
        hmac.init(secretKeySpec);
        byte[] prk = hmac.doFinal(sharedSecretBytes);
        serverEncrypt = new SecretKeySpec(Helpers.hdkfExpand(prk, "server encrypt"), "AES");
        clientEncrypt = new SecretKeySpec(Helpers.hdkfExpand(serverEncrypt.getEncoded(), "client encrypt"), "AES");
        serverMAC = new SecretKeySpec(Helpers.hdkfExpand(clientEncrypt.getEncoded(), "server MAC"), "AES");
        clientMAC = new SecretKeySpec(Helpers.hdkfExpand(serverMAC.getEncoded(), "client MAC"), "AES");
        serverIV = new IvParameterSpec(Helpers.hdkfExpand(clientMAC.getEncoded(), "server IV"));
        clientIV = new IvParameterSpec(Helpers.hdkfExpand(serverIV.getIV(), "client IV"));
    }

    public static void main(String[] args) {
        try{
            System.out.println("Server Starting.");
            Server server = new Server();
            System.out.println("Server running on port " + PORT);

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(server.socket.getOutputStream());
            objectOutputStream.flush();
            ObjectInputStream objectInputStream = new ObjectInputStream(server.socket.getInputStream());
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

            // Receive nonce
            server.nonce = (byte[]) objectInputStream.readObject();
            byteStream.write(server.nonce);

            // Send Server Cert, DH Key, Signed Key
            objectOutputStream.writeObject(server.signedServerCert);
            byteStream.write(server.signedServerCert.getEncoded());
            objectOutputStream.writeObject(server.dhPublic);
            byteStream.write(server.dhPublic.toByteArray());
            objectOutputStream.writeObject(server.signedKey);
            byteStream.write(server.signedKey);

            // Receive Client Cert, DH Key, Signed Key
            Certificate clientCert = (Certificate) objectInputStream.readObject();
            byteStream.write(clientCert.getEncoded());
            BigInteger clientDHKey = (BigInteger) objectInputStream.readObject();
            byteStream.write(clientDHKey.toByteArray());
            byte[] clientSignedKey = (byte[]) objectInputStream.readObject();
            byteStream.write(clientSignedKey);

            // Verify Client
            boolean clientVerified = Helpers.verifySig(clientCert, clientDHKey, clientSignedKey);
            if(!clientVerified) {
                System.out.println("Could not verify client. Exiting.");
                System.exit(-1);
            }

            // Calculate Shared Secret
            BigInteger sharedSecret = Helpers.getDHShared(clientDHKey, server.dhPrivate);

            // Get MAC Keys
            makeSecretKeys(server.nonce, sharedSecret);

            // Server sends MAC(All Messages + Server MAC key)
            byte[] macMessage = Helpers.macMessage(byteStream.toByteArray(), serverMAC);
            objectOutputStream.writeObject(macMessage);

            // Receive Client Response
            byte[] clientLog = (byte[]) objectInputStream.readObject();
            byteStream.writeBytes(macMessage);
            byte[] serverLog = Helpers.macMessage(byteStream.toByteArray(), clientMAC);

            // Compare Logs
            if(! Arrays.equals(clientLog, serverLog)) {
                System.out.println("Logs not verified, closing connection.");
                System.exit(-1);
            }

            // Get large file to send
            FileInputStream fileInput = new FileInputStream(server.outputFile);
            byte[] fileBytes = fileInput.readAllBytes();
            byte[] macFileBytes = Helpers.macMessage(fileBytes, serverEncrypt);
            byte[] concatFile = Helpers.concat(fileBytes, macFileBytes);

            // Create Cipher
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, serverEncrypt, serverIV);
            byte[] encrypted = cipher.doFinal(concatFile);
            objectOutputStream.writeObject(encrypted);

            // Get Client receipt message
            byte[] clientReceipt = (byte[]) objectInputStream.readObject();
            cipher.init(Cipher.DECRYPT_MODE, clientEncrypt, clientIV);
            byte[] decryptReceipt = cipher.doFinal(clientReceipt);
            byte[] decrypted = Arrays.copyOf(decryptReceipt, decryptReceipt.length - 32);
            String receipt = new String(decrypted);
            System.out.println("Client Receipt: " + receipt);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Server Exception: " + e.getMessage());
        }
    }

}
