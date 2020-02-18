import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {

    private SessionKey sessionKey;
    private String IV;

    public SessionDecrypter(String key, String iv){
        sessionKey = new SessionKey(key);
        IV = iv;
    }

    public CipherInputStream openCipherInputStream(InputStream input) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(sessionKey.ALGORITHM+"/CTR/NoPadding");
        cipher.init(cipher.DECRYPT_MODE, sessionKey.getKey(), new IvParameterSpec(Base64.getDecoder().decode(IV)));
        CipherInputStream cipherInputStream = new CipherInputStream(input,cipher);
        return cipherInputStream;
    }
}
