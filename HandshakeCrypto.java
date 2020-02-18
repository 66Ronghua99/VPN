import javax.crypto.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;


public class HandshakeCrypto {

    public static String ALGORITHM = "RSA";
    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(HandshakeCrypto.ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE,key);
        byte[] bytes = cipher.doFinal(plaintext);
        return bytes;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(HandshakeCrypto.ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,key);
        byte[] bytes = cipher.doFinal(ciphertext);
        return bytes;
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws Exception {

        FileInputStream fis = new FileInputStream(certfile);
        CertificateFactory f = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)f.generateCertificate(fis);
        PublicKey publicKey = certificate.getPublicKey();
        return publicKey;
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        File f = new File(keyfile);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int) f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
        return myPrivKey;
    }

}
