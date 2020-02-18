import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Base64;


public class SessionEncrypter {
    private int keyLength;
    private SessionKey sessionKey;
    private String IV;

    public SessionEncrypter(String key, String iv){
        sessionKey = new SessionKey(key);
        IV = iv;
    }

    public SessionEncrypter(Integer keyLength) throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.keyLength = keyLength;
        sessionKey = new SessionKey(keyLength);
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        IV = Base64.getEncoder().encodeToString(bytes);
    }

    CipherOutputStream openCipherOutputStream(OutputStream output) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(sessionKey.ALGORITHM+"/CTR/NoPadding");
        cipher.init(cipher.ENCRYPT_MODE, sessionKey.getKey(), new IvParameterSpec(Base64.getDecoder().decode(IV)));
        CipherOutputStream cipherOutputStream = new CipherOutputStream(output,cipher);
        return cipherOutputStream;
    }


    String encodeKey(){ return sessionKey.getEncodedKey(); }

    String encodeIV(){
        return IV;
    }


}
