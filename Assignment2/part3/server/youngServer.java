import java.net.*;
import java.io.*;

public class youngServer {
    // socket port
    public final static int SOCKET_PORT = 3000;
    // file name to be received
    public final static String FILE = "rootca.crt";
    public static void main(String []args) {
        try {
            // create server socket
            ServerSocket serverSocket = new ServerSocket(SOCKET_PORT);
            System.out.println("Waiting for Client...");
                try {
                    // connect to client socket
                    Socket socket = serverSocket.accept();
                    System.out.println("Connection made : " + socket);

                    // receive file from client
                    byte[] b = new byte [6000000];
                    InputStream is = socket.getInputStream();
                    FileOutputStream fos = new FileOutputStream(FILE);
                    BufferedOutputStream bos = new BufferedOutputStream(fos);
                    int bytesRead = is.read(b,0,b.length);
                    int current = bytesRead;
                    
                    // take in all bytes
                    do {
                        bytesRead = is.read(b, current, (b.length-current));
                        if(bytesRead >= 0) current += bytesRead;
                    } while (bytesRead > -1);

                    // create file with received data
                    bos.write(b, 0, current);
                    bos.flush();
                    System.out.println("File " + FILE + "downloaded (" + current + "bytes read)");
                    
                    // close all resources
                    fos.close();
                    bos.close();
                    serverSocket.close();
                } catch (IOException err) {
                    err.printStackTrace();
                }
        }   catch (IOException err) {
            err.printStackTrace();
        }
    }
}
