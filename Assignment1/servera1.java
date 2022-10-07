import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class servera1 {
    // AES_GCM Variables
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    // Utils
    private final static String OUTPUT_FORMAT = "%-30s:%s";

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
                System.out.println("------ Server Information ------");
                System.out.println(String.format(OUTPUT_FORMAT, "Server Port", server.getLocalPort()));

                try {
                    Socket socket = server.accept();
                    System.out.println("\nClient connection established from " + socket.getRemoteSocketAddress());
                    handleClient(socket);
                } catch (Exception exception) {
                    exception.getStackTrace();
                }
            }
            server.close();
        } catch(Exception exception) {
            exception.getStackTrace();
        } 
    }

    public static void handleClient(Socket conn) throws Exception {
        OutputStream output = new DataOutputStream(conn.getOutputStream());
        InputStream input = new DataInputStream(conn.getInputStream());

        // Read and construct client public key
        PublicKey client_pk = getClientPublicKey(input);

        // Generate Server Keys & Send Public Key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair serverKeyPair = kpg.generateKeyPair();
        output.write(serverKeyPair.getPublic().getEncoded());

        byte[] derivedKey = getDerivedKey(client_pk, serverKeyPair);

        byte[] encryptedText =  input.readAllBytes();

        SecretKey secretKey = new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES");

        System.out.println("\n------ AES GCM Decryption ------");
        System.out.println(String.format(OUTPUT_FORMAT, "Input (hex)", hex(encryptedText)));
        System.out.println(String.format(OUTPUT_FORMAT, "Key (hex)", hex(secretKey.getEncoded())));

        String decryptedText = decryptWithPrefixIV(encryptedText, secretKey);

        System.out.println(String.format(OUTPUT_FORMAT, "Decrypted (plain text)", decryptedText));
    }

    public static PublicKey getClientPublicKey(InputStream input) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] buffer = new byte[91];
        input.read(buffer);

        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec pkSpec = new X509EncodedKeySpec(buffer);
        return kf.generatePublic(pkSpec);
    }

    public static byte[] getDerivedKey(PublicKey clientPublicKey, KeyPair serverKeyPair) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(serverKeyPair.getPrivate());
        ka.doPhase(clientPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        
        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(serverKeyPair.getPublic().getEncoded()), ByteBuffer.wrap(clientPublicKey.getEncoded()));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));
        return hash.digest();
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public static String decrypt(byte[] cText, SecretKey secret, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cText);
        return new String(plainText, UTF_8);
    }

    public static String decryptWithPrefixIV(byte[] cText, SecretKey secret) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(cText);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);

        String plainText = decrypt(cipherText, secret, iv);
        return plainText;
    }
}