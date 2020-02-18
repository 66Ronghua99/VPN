/**
 * Port forwarding server. Forward data
 * between two TCP ports. Based on Nakov TCP Socket Forward Server 
 * and adapted for IK2206.
 *
 * Original copyright notice below.
 * (c) 2018 Peter Sjodin, KTH
 */

/**
 * Nakov TCP Socket Forward Server - freeware
 * Version 1.0 - March, 2002
 * (c) 2001 by Svetlin Nakov - http://www.nakov.com
 */
 
import java.io.*;
import java.lang.AssertionError;
import java.lang.Integer;
import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;
import java.util.StringTokenizer;
 
public class ForwardServer
{
    private static final boolean ENABLE_LOGGING = true;
    public static final int DEFAULTSERVERPORT = 2206;
    public static final String DEFAULTSERVERHOST = "localhost";
    public static final String PROGRAMNAME = "ForwardServer";
    private static Arguments arguments;


    private ServerSocket handshakeSocket;
    
    private ServerSocket listenSocket;
    private String targetHost;
    private int targetPort;

    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;

    private boolean isHandShakeFinish = false;
    
    /**
     * Do handshake negotiation with client to authenticate, learn 
     * target host/port, etc.
     */
    private void doHandshake() throws UnknownHostException, IOException, Exception {

        Socket clientSocket = handshakeSocket.accept();
        String clientHostPort = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Logger.log("Incoming handshake connection from " + clientHostPort);

        /* This is where the handshake should take place */
        //exchanging the certificate as well as making a new sessionKey
        HandshakeMessage handshakeMessage = new HandshakeMessage();
        HandshakeCrypto handshakeCrypto = new HandshakeCrypto();
        VerifyCertificate verifyCertificate = new VerifyCertificate(arguments.get("cacert"));
        sessionEncrypter = new SessionEncrypter(128);
        sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(),sessionEncrypter.encodeIV());
        PrivateKey privateKey = handshakeCrypto.getPrivateKeyFromKeyFile(arguments.get("key"));
        String messageType;

        //Receive Certificate
        handshakeMessage.recv(clientSocket);
        messageType = handshakeMessage.getParameter("MessageType");
        if(messageType.equals("ClientHello")) {
            byte[] plainClientCrt = Base64.getDecoder().decode(handshakeMessage.getParameter("Certificate"));
            System.out.println("Certificate received!!");

            boolean isValid = verifyCertificate.verify(plainClientCrt);
            if(isValid){
                FileOutputStream fo = new FileOutputStream("bbb");
                fo.write(plainClientCrt);
                PublicKey publicKey = handshakeCrypto.getPublicKeyFromCertFile("bbb");//get publicKey from a file
                FileInputStream serverCrt = new FileInputStream(arguments.get("usercert"));//send the certificate
                String plainServerCrt = Base64.getEncoder().encodeToString(serverCrt.readAllBytes());

                handshakeMessage.putParameter("MessageType","ServerHello");
                handshakeMessage.putParameter("Certificate",plainServerCrt);
                handshakeMessage.send(clientSocket);
                System.out.println("Certificate sent!!");

                //Receiving "Forward"
                handshakeMessage.recv(clientSocket);
                messageType = handshakeMessage.getParameter("MessageType");

                if(messageType.equals("Forward")){
                    String plainTargetHost = handshakeMessage.getParameter("TargetHost");//get the target IP address and port
                    String plainTargetPort = handshakeMessage.getParameter("TargetPort");

                    String cipherSessionKey = Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(Base64.getDecoder().decode(sessionEncrypter.encodeKey()),publicKey));
                    String cipherSessionIV = Base64.getEncoder().encodeToString(handshakeCrypto.encrypt(Base64.getDecoder().decode(sessionEncrypter.encodeIV()),publicKey));
                    String cipherSessionHost = Handshake.serverHost;
                    String cipherSessionPort = String.valueOf(Handshake.serverPort);

                    handshakeMessage.setProperty("MessageType","Session");
                    handshakeMessage.putParameter("SessionKey",cipherSessionKey);
                    handshakeMessage.putParameter("SessionIV",cipherSessionIV);
                    handshakeMessage.putParameter("SessionHost",cipherSessionHost);
                    handshakeMessage.putParameter("SessionPort",cipherSessionPort);
                    handshakeMessage.send(clientSocket);
                    System.out.println("Session sent!!");
                    isHandShakeFinish = true;
                    clientSocket.close();

                    /*
                     * Fake the handshake result with static parameters.
                     */

                    /* listenSocket is a new socket where the ForwardServer waits for the
                     * client to connect. The ForwardServer creates this socket and communicates
                     * the socket's address to the ForwardClient during the handshake, so that the
                     * ForwardClient knows to where it should connect (ServerHost/ServerPort parameters).
                     * Here, we use a static address instead (serverHost/serverPort).
                     * (This may give "Address already in use" errors, but that's OK for now.)
                     */
                    listenSocket = new ServerSocket();
                    listenSocket.bind(new InetSocketAddress(Handshake.serverHost, Handshake.serverPort));
                    Logger.log("ServerSocket on"+Handshake.serverHost+":"+Handshake.serverPort+"starts!!");
                    /* The final destination. The ForwardServer sets up port forwarding
                     * between the listensocket (ie., ServerHost/ServerPort) and the target.
                     */
                    targetHost = plainTargetHost;
                    targetPort = Integer.parseInt(plainTargetPort);
                }else{
                    clientSocket.close();// not "Forward"
                }
            }else{
                clientSocket.close();//certificate is not valid
            }
        }else {
                clientSocket.close();//not clienthello
        }


    }

    /**
     * Starts the forward server - binds on a given port and starts serving
     */
    public void startForwardServer()
    //throws IOException
        throws Exception
    {
 
        // Bind server on given TCP port
        int port = Integer.parseInt(arguments.get("handshakeport"));
        try {
            handshakeSocket = new ServerSocket(port);
        } catch (IOException ioe) {
            throw new IOException("Unable to bind to port " + port + ": " + ioe);
        }

        log("Nakov Forward Server started on TCP port " + port);
 
        // Accept client connections and process them until stopped
        while(true) {
            ForwardServerClientThread forwardThread;
            try{
                doHandshake();
            }catch (SocketException e){
                System.out.println("Socket connection is down!!");
            }
            if (isHandShakeFinish){
                forwardThread = new ForwardServerClientThread(this.listenSocket, this.targetHost, this.targetPort, sessionEncrypter,sessionDecrypter);
                forwardThread.start();
            }
        }
    }
 
    /**
     * Prints given log message on the standart output if logging is enabled,
     * otherwise ignores it
     */
    public void log(String aMessage)
    {
        if (ENABLE_LOGGING)
           System.out.println(aMessage);
    }
 
    static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--handshakehost=<hostname>");
        System.err.println(indent + "--handshakeport=<portnumber>");        
        System.err.println(indent + "--usercert=<filename>");
        System.err.println(indent + "--cacert=<filename>");
        System.err.println(indent + "--key=<filename>");                
    }
    
    /**
     * Program entry point. Reads settings, starts check-alive thread and
     * the forward server
     */
    public static void main(String[] args)
        throws Exception
    {
        arguments = new Arguments();
        arguments.setDefault("handshakeport", Integer.toString(DEFAULTSERVERPORT));
        arguments.setDefault("handshakehost", DEFAULTSERVERHOST);
        arguments.loadArguments(args);
        
        ForwardServer srv = new ForwardServer();
        srv.startForwardServer();
    }
 
}
