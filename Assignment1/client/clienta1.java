import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
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

            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            
            // Generate Client Keys & Send Public Key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();;
            output.write(kp.getPublic().getEncoded());
            
            // Read and construct server public key
            byte[] buffer = new byte[91];
            input.read(buffer);
            KeyFactory kf = KeyFactory.getInstance("EC");
            EncodedKeySpec pkSpec = new X509EncodedKeySpec(buffer);
            PublicKey server_pk = kf.generatePublic(pkSpec);

            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(server_pk, true);
            byte[] sharedSecret = ka.generateSecret();
            System.out.println("Shared Secret: " + sharedSecret);
            
            // Derive a key from the shared secret and both public keys
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret);
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(kp.getPublic().getEncoded()), ByteBuffer.wrap(server_pk.getEncoded()));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));

            byte[] derivedKey = hash.digest();
            BigInteger bigint = new BigInteger(derivedKey);
            System.out.printf("Final key: %s%n", bigint.toString(16));

            Scanner scan = new Scanner(System.in);
            System.out.println("Enter a short message:");
            String message = scan.nextLine();
            scan.close();
            System.out.println(message);

            // Closes all connections
            output.close();
            input.close();
            socket.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}