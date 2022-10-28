import java.net.*;
import java.io.*;

public class youngClient {
    // socket constants
    public final static String SERVER = "127.0.0.1";
    public final static int SOCKET_PORT = 3000;
    // removes hardcoding of file path
    public final static String FILE = (new File("rootca.crt").getAbsolutePath());

    public static void main(String[] args) {
        // provide file path of certificate
        System.out.println(FILE);
        try {
            // create socket
            Socket socket = new Socket(SERVER, SOCKET_PORT);
            
            // send file
            // create certificate file with path of certificate
            File certificate = new File(FILE);
            
            // byte array to contain information to send
            byte[] b = new byte[(int)certificate.length()];

            // for purposes of transport of data
            FileInputStream fis = new FileInputStream(certificate);
            BufferedInputStream bis = new BufferedInputStream(fis);

            // get certificate data
            bis.read(b,0,b.length);

            // send data to server
            OutputStream os = socket.getOutputStream();
            System.out.println("Sending " + FILE + "(" + b.length + " bytes)");
            os.write(b,0,b.length);
            os.flush();
            
            // confirm completion, and finish using resources
            System.out.println("Certificate Transfer Complete! ");
            bis.close();
            os.close();
            socket.close();
        } catch (IOException err) {
            err.printStackTrace();
        }
    }
}