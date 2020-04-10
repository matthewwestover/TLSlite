package client;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;

public class Client {
    // These paths assume compiled in command line via
    // javac *.java in the client package folder
    // and java client.Client ran in the src folder
    private String clientCert = "./resources/certs/CASignedClientCertificate.pem";
    private String clientPrivateKey = "./resources/keys/clientPrivateKey.der";
    private String encryptFile = "./resources/testEncrypted.txt";
    private String decryptedFile = "./resources/testClientDecrypted.txt";
    private static int PORT = 8080;
    private Socket socket;
    private Certificate signedClientCert;
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
    public Client() {
        try{
            SecureRandom random = new SecureRandom();
            this.nonce = Helpers.getNonce();
            this.signedClientCert = Helpers.getCert(clientCert);
            this.rsaPrivate = Helpers.getRSAPrivKey(clientPrivateKey);
            this.dhPrivate = new BigInteger(Integer.toString(random.nextInt()));
            this.dhPublic = Helpers.getDHKey(dhPrivate);
            this.signedKey = Helpers.getSignedKey(rsaPrivate, dhPublic);
            this.socket = new Socket("127.0.0.1", PORT);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Client initialization error: " + e.getMessage());
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
            System.out.println("Client Starting.");
            Client client = new Client();
            System.out.println("Client Running. Contacting Server on port: " + PORT);

            ObjectOutputStream objectOutputStream = new ObjectOutputStream(client.socket.getOutputStream());
            objectOutputStream.flush();
            ObjectInputStream objectInputStream = new ObjectInputStream(client.socket.getInputStream());
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();

            // Send Nonce
            objectOutputStream.writeObject(client.nonce);
            byteStream.write(client.nonce);

            // Receive Server Cert, DH Key, Signed Key
            Certificate serverCert = (Certificate) objectInputStream.readObject();
            byteStream.write(serverCert.getEncoded());
            BigInteger serverDHKey = (BigInteger) objectInputStream.readObject();
            byteStream.write(serverDHKey.toByteArray());
            byte[] serverSignedKey = (byte[]) objectInputStream.readObject();
            byteStream.write(serverSignedKey);

            // Send Client Cert, DH Key, Signed Key
            objectOutputStream.writeObject(client.signedClientCert);
            byteStream.write(client.signedClientCert.getEncoded());
            objectOutputStream.writeObject(client.dhPublic);
            byteStream.write(client.dhPublic.toByteArray());
            objectOutputStream.writeObject(client.signedKey);
            byteStream.write(client.signedKey);

            // Verify Server
            boolean serverVerified = Helpers.verifySig(serverCert, serverDHKey, serverSignedKey);
            if(!serverVerified) {
                System.out.println("Could not verify server. Exiting.");
                System.exit(-1);
            }

            // Calculate Shared Secret
            BigInteger sharedSecret = Helpers.getDHShared(serverDHKey, client.dhPrivate);

            // Get MAC Keys
            makeSecretKeys(client.nonce, sharedSecret);

            // Receive Server MAC(All Messages + Server MAC Key)
            byte[] serverLog = (byte[]) objectInputStream.readObject();
            byte[] clientLog = Helpers.macMessage(byteStream.toByteArray(), serverMAC);

            // Compare Logs
            if( !Arrays.equals(clientLog, serverLog)) {
                System.out.println("Logs not verified closing connection.");
                System.exit(-1);
            }

            // Send updated log to Server for Server Verification
            byteStream.writeBytes(serverLog);
            byte[] macMessage = Helpers.macMessage(byteStream.toByteArray(), clientMAC);
            objectOutputStream.writeObject(macMessage);

            // Get encrypted file
            byte[] encrypted = (byte []) objectInputStream.readObject();
            // Output to show encryption
            FileOutputStream fileOutputStream1 = new FileOutputStream(client.encryptFile);
            fileOutputStream1.write(encrypted);
            fileOutputStream1.close();

            // Decrypt the file
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverEncrypt, serverIV);
            byte[] decrypted = cipher.doFinal(encrypted);
            FileOutputStream fileOutputStream2 = new FileOutputStream(client.decryptedFile);
            fileOutputStream2.write(decrypted);

            String receipt = "File has been received by client.";
            cipher.init(Cipher.ENCRYPT_MODE, clientEncrypt, clientIV);
            byte[] macReceipt = Helpers.macMessage(receipt.getBytes(), clientEncrypt);
            byte[] concatReceipt = Helpers.concat(receipt.getBytes(), macReceipt);
            objectOutputStream.writeObject(cipher.doFinal(concatReceipt));

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Client Exception: " + e.getMessage());
        }
    }
}
