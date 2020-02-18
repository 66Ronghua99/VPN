/**
 * Port forwarding client. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * See original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */

 
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.lang.AssertionError;
import java.lang.IllegalArgumentException;
import java.lang.Integer;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

public class ForwardClient
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardClient";

    private static Arguments arguments;
    private static int serverPort;
    private static String serverHost;

    private static SessionEncrypter sessionEncrypter;
    private static SessionDecrypter sessionDecrypter;


    private static void doHandshake() throws Exception {

        /* Connect to forward server server */
        System.out.println("Connect to " + arguments.get("handshakehost") + ":" + Integer.parseInt(arguments.get("handshakeport")));
        Socket socket = new Socket(arguments.get("handshakehost"), Integer.parseInt(arguments.get("handshakeport")));

        /* This is where the handshake should take place */
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto();
        VerifyCertificate verifyCertificate = new VerifyCertificate(arguments.get("cacert"));
        PrivateKey privateKey = handshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key")); //get the privateKey of Client

        //Say Hello and send Certificate
        FileInputStream clientCrt = new FileInputStream(arguments.get("usercert"));//send the certificate
        String plainCrt = Base64.getEncoder().encodeToString(clientCrt.readAllBytes());
        handshakeMessage.putParameter("MessageType","ClientHello");
        handshakeMessage.putParameter("Certificate",plainCrt);
        handshakeMessage.send(socket);
        System.out.println("Certificate sent!!");

        //Receive Certificate
        handshakeMessage.recv(socket);
        String messageType = handshakeMessage.getParameter("MessageType");
        if(messageType.equals("ServerHello")){
            byte[] plainServerCrt = Base64.getDecoder().decode(handshakeMessage.getParameter("Certificate"));
            System.out.println("Certificate received!!");

            boolean isValid = verifyCertificate.verify(plainServerCrt);
            if (isValid) {
                //extract publickey
                FileOutputStream fo = new FileOutputStream("aaa");
                fo.write(plainServerCrt);
                PublicKey publicKey = handshakeCrypto.getPublicKeyFromCertFile("aaa");

                //Send Target
//                String plainTargetHost = Base64.getEncoder().encodeToString(arguments.get("targethost").getBytes()); //still needs improve here
//                String plainTargetPort = Base64.getEncoder().encodeToString(arguments.get("targetport").getBytes());
                handshakeMessage.putParameter("MessageType","Forward");
                handshakeMessage.putParameter("TargetHost",arguments.get("targethost"));
                handshakeMessage.putParameter("TargetPort",arguments.get("targetport"));
                handshakeMessage.send(socket);
                System.out.println("Target sent");

                //Receive Session
                handshakeMessage.recv(socket);
                messageType = handshakeMessage.getProperty("MessageType");
                if(messageType.equals("Session")){
                    byte[] cipherS = Base64.getDecoder().decode(handshakeMessage.getParameter("SessionKey"));
                    String plainSessionKey = Base64.getEncoder().encodeToString(handshakeCrypto.decrypt(cipherS,privateKey));
                    cipherS = Base64.getDecoder().decode(handshakeMessage.getParameter("SessionIV"));
                    String plainSessionIV = Base64.getEncoder().encodeToString(handshakeCrypto.decrypt(cipherS,privateKey));
//                    cipherS = Base64.getDecoder().decode(handshakeMessage.getParameter("SessionHost"));
//                    String plainSessionHost = new String(handshakeCrypto.decrypt(cipherS,privateKey));
                    String plainSessionHost = handshakeMessage.getParameter("SessionHost");
//                    cipherS = Base64.getDecoder().decode(handshakeMessage.getParameter("SessionPort"));
//                    String plainSessionPort = new String(handshakeCrypto.decrypt(cipherS,privateKey));
                    String plainSessionPort = handshakeMessage.getParameter("SessionPort");
                    System.out.println("sessionKey received!!");

                    sessionEncrypter = new SessionEncrypter(plainSessionKey,plainSessionIV);
                    sessionDecrypter = new SessionDecrypter(plainSessionKey,plainSessionIV);
                    //session needs to be forwarded to ForwardThread
                    socket.close();

                    /*
                     * Fake the handshake result with static parameters.
                     */

                    /* This is to where the ForwardClient should connect.
                     * The ForwardServer creates a socket
                     * dynamically and communicates the address (hostname and port number)
                     * to ForwardClient during the handshake (ServerHost, ServerPort parameters).
                     * Here, we use a static address instead.
                     */
                    serverHost = plainSessionHost;
                    serverPort = Integer.parseInt(plainSessionPort);
                }else{
                    socket.close();//stop the connection, it's not the Session information
                }
            }else{
                socket.close();//stop the connection, it's not a ServerHello
            }
        }else{
            socket.close();//stop the connection, the certificate is not valid
        }
    }
    /*
     * Let user know that we are waiting
     */
    private static void tellUser(ServerSocket listensocket) throws UnknownHostException {
        System.out.println("Client forwarder to target " + arguments.get("targethost") + ":" + arguments.get("targetport"));
        System.out.println("Waiting for incoming connections at " +
                           InetAddress.getLocalHost().getHostAddress() + ":" + listensocket.getLocalPort());
    }
        
    /*
     * Set up client forwarder.
     * Run handshake negotiation, then set up a listening socket and wait for user.
     * When user has connected, start port forwarder thread.
     */
    static public void startForwardClient() throws Exception {

        doHandshake();

        // Wait for client. Accept one connection.

        ForwardServerClientThread forwardThread;
        ServerSocket listensocket;
        
        /* Create a new socket. This is to where the user should connect.
         * ForwardClient sets up port forwarding between this socket
         * and the ServerHost/ServerPort learned from the handshake */
        listensocket = new ServerSocket();
        /* Let the system pick a port number */
        listensocket.bind(null);
        /* Tell the user, so the user knows wheare to connect */
        tellUser(listensocket);

        Socket clientSocket = listensocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        log("Accepted client from " + clientHostPort);
            
        forwardThread = new ForwardServerClientThread(clientSocket, serverHost, serverPort, sessionEncrypter, sessionDecrypter);
        forwardThread.start();
    }

    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public static void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--targethost=<hostname>");
        System.err.println(indent + "--targetport=<portnumber>");        
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads arguments and run
     * the forward server
     */
    public static void main(String[] args) throws Exception {
        try {
            arguments = new Arguments();
            arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
            arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
            arguments.loadArguments(args);
            if (arguments.get("targetport") == null || arguments.get("targethost") == null) {
                throw new IllegalArgumentException("Target not specified");
            }
        } catch(IllegalArgumentException ex) {
            System.out.println(ex);
            usage();
            System.exit(1);
        }
        startForwardClient();
    }
}
