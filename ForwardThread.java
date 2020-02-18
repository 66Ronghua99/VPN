/**
 * ForwardThread handles the TCP forwarding between a socket input stream (source)
 * and a socket output stream (destination). It reads the input stream and forwards
 * everything to the output stream. If some of the streams fails, the forwarding
 * is stopped and the parent thread is notified to close all its connections.
 */
 
import javax.crypto.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class ForwardThread extends Thread
{
private static final int READ_BUFFER_SIZE = 8192;
 
    InputStream mInputStream = null;
    OutputStream mOutputStream = null;
    ForwardServerClientThread mParent = null;
    boolean isEncrypted;

 
    /**
     * Creates a new traffic forward thread specifying its input stream,
     * output stream and parent thread
     */
    public ForwardThread(ForwardServerClientThread aParent, InputStream aInputStream, OutputStream aOutputStream, boolean isEncrypted)
    {
        mInputStream = aInputStream;
        mOutputStream = aOutputStream;
        mParent = aParent;
        this.isEncrypted = isEncrypted;
    }

 
    /**
     * Runs the thread. Until it is possible, reads the input stream and puts read
     * data in the output stream. If reading can not be done (due to exception or
     * when the stream is at his end) or writing is failed, exits the thread.
     */
    public void run()
    {
        byte[] buffer = new byte[READ_BUFFER_SIZE];
        try {
            if(mParent.isClient) {
                if (isEncrypted) {
                    CipherOutputStream cos = mParent.se.openCipherOutputStream(mOutputStream);
                    while (true) {
                        int bytesRead = mInputStream.read(buffer);
                        if (bytesRead == -1)
                            break; // End of stream is reached --> exit the thread
                        cos.write(buffer, 0, bytesRead);
                    }
                } else {
                    CipherInputStream cis = mParent.sd.openCipherInputStream(mInputStream);
                    while (true) {
                        int bytesRead = cis.read(buffer);
                        if (bytesRead == -1)
                            break; // End of stream is reached --> exit the thread
                        mOutputStream.write(buffer, 0, bytesRead);
                    }
                }
            }
            //on the server side
            else{
                if(isEncrypted){
                    CipherInputStream cis = mParent.sd.openCipherInputStream(mInputStream);
                    while(true){
                        int bytesRead = cis.read(buffer);
                        if (bytesRead == -1)
                            break; // End of stream is reached --> exit the thread
                        mOutputStream.write(buffer, 0, bytesRead);
                    }
                }else {
                    CipherOutputStream cos = mParent.se.openCipherOutputStream(mOutputStream);
                    while (true) {
                        int bytesRead = mInputStream.read(buffer);
                        if (bytesRead == -1)
                            break; // End of stream is reached --> exit the thread
                        cos.write(buffer, 0, bytesRead);
                    }
                }
            }
        } catch (IOException e) {
            // Read/write failed --> connection is broken --> exit the thread
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        // Notify parent thread that the connection is broken and forwarding should stop
        mParent.connectionBroken();
    }
}
