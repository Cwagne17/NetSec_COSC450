import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.io.Console;

import java.util.*;
import java.util.logging.*;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;

import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

import java.nio.ByteBuffer;

public class clienta1 {

    // Utils
    private final static Logger logger = Logger.getAnonymousLogger();

    public static void main(String[] args) {
        try {
            // Creates new Socket
            Socket socket = new Socket("127.0.0.1", 3000);
            if (!socket.isConnected()) {
                logger.log(Level.SEVERE, "Can't connect to socket");
                System.exit(1);
            }
            logger.log(Level.INFO, "Client connected at " + socket.getLocalPort());


            // Inits the I/O Objects
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);
            
            KeyPair kp = generateKeys();
            output.println(kp.getPublic().getEncoded());

            long val = Integer.parseInt(input.readLine(), 16);
            byte[] server_pk_bytes = BigInteger.valueOf(val).toByteArray();
            System.out.println("Server Public Key: " + server_pk_bytes);

            KeyFactory kf = KeyFactory.getInstance("EC");
            EncodedKeySpec pkSpec = new X509EncodedKeySpec(server_pk_bytes);
            System.out.println("pkspec: " + pkSpec.getEncoded());
            PublicKey server_pk = kf.generatePublic(pkSpec);

            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(server_pk, true);
            byte[] sharedSecret = ka.generateSecret();
            System.out.println("Shared Secret: " + sharedSecret);

            // Closes all connections
            output.close();
            input.close();
            socket.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    public static KeyPair generateKeys() throws NoSuchAlgorithmException {
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }
}