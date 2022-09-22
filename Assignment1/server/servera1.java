import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Console;

import java.util.*;
import java.util.logging.*;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;

import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import java.nio.ByteBuffer;


public class servera1 {
    // Utils
    private final static Logger logger = Logger.getAnonymousLogger();

    public static void main(String[] args) {
        try {
            // Creates socket
            ServerSocket server = new ServerSocket(3000);
            if (!server.isBound()) {
                System.out.println("Socket isn't bound");
                System.exit(1);
            }

            // Listen for clients
            if(!server.isClosed()) {
                logger.log(Level.INFO, "Server listening at " + server.getInetAddress());
                while (true) {
                    try {
                        Socket socket = server.accept();
                        handleClient(socket);
                    } catch (Exception exception) {
                        logger.log(Level.SEVERE, exception.getStackTrace().toString());
                    }
                }
            }

            server.close();
        } catch(Exception exception) {
            logger.log(Level.SEVERE, exception.getStackTrace().toString());
        } 
    }

    public static KeyPair generateKeys() throws NoSuchAlgorithmException {
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public static void handleClient(Socket conn) throws IOException, NoSuchAlgorithmException {
        BufferedReader input = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        PrintWriter output = new PrintWriter(conn.getOutputStream(), true);
        
        String line = input.readLine();
        System.out.println("Client Public Key: " + line);
    
        KeyPair kp = generateKeys();
        output.println(kp.getPublic().getEncoded());
    }
}