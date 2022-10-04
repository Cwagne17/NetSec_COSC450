# Assignment 1

## Tutorial on how to run and test the program

1. Open two terminals
2. In the first terminal type ```javac servera1.java``` to compile the server file
3. In the second terminal type ```javac clienta1.java``` to compile the client file
4. In the first terminal type ```java servera1``` to run the compiled server file
5. In the second terminal type ```java clienta1``` to run the compiled client file
6. When the Client file requests an input, type in a short message
7. The short message is now encrypted, sent to the server, and decrypted
8. Look to the server to see the output of the short message


## Indication of exact format in which a user should enter each input

This message can consist of all ASCII characters, spaces, etc. An example can be seen in the example image, but another would be the phrase "This is a secret message." There is only one opportunity for the user to enter input each time the files are run. 


## Example image of the input and output when the program is run

![alt text](https://github.com/Cwagne17/NetSec_COSC450/tree/main/Assignment1/inputandoutput.png?raw=true)


## Method used to derive key K from S

ECDH Key Exchange - client creates key and sends it to server. The server then receives the client public key. Then the server generates a public key and sends it to client. Client and server then produce a derived key using the generated public keys. 
AES 256 bits key generation - Client and server produce secret keys based off the derived key generated in previous step.
AES-GCM - Client generates random 12 byte iv to use to encrypt/ decrypt message. Client encrypts plaintext using the secret key from previous step and iv. Client sends this message to server with the iv as a prefix. Server decrypts using secret key along with the iv. The process is completed, the plaintext has been encrypted, sent to the server, then decrypted to be returned to plaintext. 