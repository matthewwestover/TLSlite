package client;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Helpers {
    // Got values for generator and prime from https://www.ietf.org/rfc/rfc3526.txt
    private static final BigInteger DH_GENERATOR = new BigInteger("2");
    private static final BigInteger DH_PRIME = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);

    public static BigInteger getDHKey(BigInteger privateKey) {
        return DH_GENERATOR.modPow(privateKey, DH_PRIME);
    }

    public static BigInteger getDHShared(BigInteger dhKey, BigInteger privateKey) {
        return dhKey.modPow(privateKey, DH_PRIME);
    }

    public static byte[] getNonce() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] nonce = new byte[32];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    public static Certificate getCert(String fileName) throws FileNotFoundException, CertificateException {
        InputStream input = new FileInputStream(fileName);
        // X.509 was used in creating certificates with openssl. It is standard.
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return cf.generateCertificate(input);
    }

    public static boolean verifyCert(Certificate cert) {
        try {
            Certificate caCert = getCert("./resources/certs/CAcertificate.pem");
            cert.verify(caCert.getPublicKey());
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // Should read from the .der file
    public static PrivateKey getRSAPrivKey(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        InputStream input = new FileInputStream(fileName);
        byte[] byteArr = input.readAllBytes();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(byteArr);
        // Used RSA format with openssl command
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    public static byte[] getSignedKey(PrivateKey privateKey, BigInteger publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateKey);
        signature.update(publicKey.toByteArray());
        return signature.sign();
    }

    public static boolean verifySig(Certificate cert, BigInteger publicKey, byte[] signedKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if(!verifyCert(cert)){
            return false;
        }
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(cert);
        signature.update(publicKey.toByteArray());
        return signature.verify(signedKey);
    }

    // Key derivation function - returns first 16 bytes
    public static byte[] hdkfExpand(byte[] input, String tag) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(input, "HmacSHA256");
        hmac.init(secretKey);
        // data = tag bytes concatenated with a byte value of 1
        byte[] data = new byte[tag.getBytes().length+1];
        System.arraycopy(tag.getBytes(), 0, data, 0, data.length - 1); // Intellij suggested this over a for loop
        data[data.length-1] = 1;
        byte[] okm = hmac.doFinal(data);
        byte[] output = new byte[16];
        System.arraycopy(okm, 0, output, 0, output.length); // Intellij suggested this over a for loop
        return output;
    }

    public static byte[] macMessage(byte[] message, SecretKeySpec key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(key);
        return hmac.doFinal(message);
    }

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] output = new byte[first.length + second.length];
        int j = 0;
        for(int i = 0; i < output.length; i++) {
            if(i < first.length) {
                output[i] = first[i];
            } else {
                output[i] = second[j];
                j++;
            }
        }
        return output;
    }

}
