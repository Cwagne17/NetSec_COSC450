
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
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
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class clienta1 {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

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
            logger.log(Level.INFO, "Client connected to " + socket.getInetAddress() + ":" + socket.getPort());
            
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            DataInputStream input = new DataInputStream(socket.getInputStream());

            // ECDH key exchange
            KeyPair client_key_pair = generateKeyPair(output);
            PublicKey server_pk = readServerKey(input);
            byte[] derivedKey = getDerivedKey(server_pk, client_key_pair);

            // Get user input
            String plaintext = getClientInput();

            // encrypt and decrypt need the same key.
            // get AES 256 bits (32 bytes) key
            SecretKey secretKey = new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES");

            // encrypt and decrypt need the same IV.
            // AES-GCM needs IV 96-bit (12 bytes)
            byte[] iv = getRandomNonce(IV_LENGTH_BYTE);
            byte[] encryptedText = encryptWithPrefixIV(plaintext.getBytes(UTF_8), secretKey, iv);

            String OUTPUT_FORMAT = "%-30s:%s";
            System.out.println("\n------ AES GCM Encryption ------");
            System.out.println(String.format(OUTPUT_FORMAT, "Input (plain text)", plaintext));
            System.out.println(String.format(OUTPUT_FORMAT, "Derived Key (hex)", hex(secretKey.getEncoded())));
            System.out.println(String.format(OUTPUT_FORMAT, "IV  (hex)", hex(iv)));
            System.out.println(String.format(OUTPUT_FORMAT, "Encrypted (hex) ", hex(encryptedText)));

            output.write(encryptedText);

            // Closes all connections
            output.close();
            socket.close();
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }

    /**
     * ECDH Key Exchange
     */

    // Generate Client Keys & Send Public Key
    public static KeyPair generateKeyPair(DataOutputStream output) throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        output.write(kp.getPublic().getEncoded());
        return kp;
    }

    // Read and construct server public key
    public static PublicKey readServerKey(InputStream input) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] buffer = new byte[91];
        input.read(buffer);

        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec pkSpec = new X509EncodedKeySpec(buffer);
        PublicKey server_pk = kf.generatePublic(pkSpec);
        return server_pk;
    }

    public static byte[] getDerivedKey(PublicKey serverPublicKey, KeyPair clientKeyPair) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException {
        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(clientKeyPair.getPrivate());
        ka.doPhase(serverPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        
        // Derive a key from the shared secret and both public keys
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        hash.update(sharedSecret);
        List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(clientKeyPair.getPublic().getEncoded()), ByteBuffer.wrap(serverPublicKey.getEncoded()));
        Collections.sort(keys);
        hash.update(keys.get(0));
        hash.update(keys.get(1));
        return hash.digest();
    }

    public static String getClientInput() {
        Scanner scan = new Scanner(System.in);
        System.out.println("\nEnter a short message:");
        String message = scan.nextLine();
        scan.close();
        return message;
    }

    /**
     * AES_GCM Encryption
     */

    public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    // hex representation
    public static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    // AES-GCM needs GCMParameterSpec
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(pText);
        return encryptedText;
    }

    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws Exception {
        byte[] cipherText = encrypt(pText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return cipherTextWithIv;
    }

}