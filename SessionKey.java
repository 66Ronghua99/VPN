import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionKey {
    public static final String ALGORITHM = "AES";
    private int keyLength;
    private String encodedKey;
    private SecretKey key;
    private String IV;

    /**
     * Constructor: using integer to generate the key
     * @param keyLength length of the key
     * @throws NoSuchAlgorithmException
     */
    public SessionKey(int keyLength) throws NoSuchAlgorithmException {
        this.keyLength = keyLength;
        keyGenerate keyGen = new keyGenerate();
        this.setKey(keyGen.generateKey(keyLength));
        this.encodeKey();
    }
    /**
     *Constructor: use the key encoded by Base64 to regenerate the original key
     * @param encodedKey
     * @throws UnsupportedEncodingException
     */
    public SessionKey(String encodedKey) {
        this.encodedKey = encodedKey;
        decodeKey();
    }

    /**
     * Encode the key with Base64
     * @return the String value of secret key encoded by Base64
     */
    public String encodeKey()  {
        Base64.Encoder encoder = Base64.getEncoder();
        this.encodedKey = new String(encoder.encode(key.getEncoded()));
        return encodedKey;
    }

    /**
     * Decode the bytes stream with Base64
     * @return secretKey
     * @throws UnsupportedEncodingException
     */
    public void decodeKey() {
        try{
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] bytes = decoder.decode(encodedKey);
            setKey(new SecretKeySpec(bytes, 0, bytes.length, ALGORITHM));//the middle two variables can be omitted
        }catch (IllegalArgumentException e){
            System.out.println("\""+encodedKey+"\""+" is not a valid value for Base64. Initialization fails!!!");
        }
    }

    /**
     * setter and getter for secret key
     * @param key
     */
    public void setKey(SecretKey key) {
        this.key = key;
    }
    public SecretKey getKey(){
        return key;
    }
    public String getEncodedKey(){ return this.encodedKey; }

    /**
     * Generate the key
     */
    class keyGenerate {

        public SecretKey generateKey(int keySize) throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);//use which method to generate key(encryption method)
            SecureRandom secureRandom = new SecureRandom();//secureRandom help generate strong secured stream of numbers
            keyGenerator.init(keySize,secureRandom);// put secure numbers into keyGenerator
            setKey(keyGenerator.generateKey());//generate a stream of secret key
            return key;
        }
    }
}
