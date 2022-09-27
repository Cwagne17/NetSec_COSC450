import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.*;
import java.util.logging.*;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;

import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
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
                        exception.getStackTrace();
                    }
                }
            }

            server.close();
        } catch(Exception exception) {
            exception.getStackTrace();
        } 
    }

    public static void handleClient(Socket conn) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        InputStream input = new DataInputStream(conn.getInputStream());
        OutputStream output = new DataOutputStream(conn.getOutputStream());

        // Read and construct client public key
        byte[] buffer = new byte[91];
        input.read(buffer);
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec pkSpec = new X509EncodedKeySpec(buffer);
        PublicKey client_pk = kf.generatePublic(pkSpec);

        // Generate Server Keys & Send Public Key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        output.write(kp.getPublic().getEncoded());

        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(client_pk, true);
        byte[] sharedSecret = ka.generateSecret();
        System.out.println("Shared Secret: " + sharedSecret);

        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(kp.getPublic().getEncoded()), ByteBuffer.wrap(client_pk.getEncoded()));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));

        byte[] derivedKey = hash.digest();
        BigInteger bigint = new BigInteger(derivedKey);
        System.out.printf("Final key: %s%n", bigint.toString(16));
    }
}