# Assignment 1

## Tutorial on how to run and test the program

Take a look at the example image to see how to compile and run java files. Be sure to run the server file first, as it will wait for the client file to be run, the client will not wait for the server to connect, it will terminate. The client, once successfully connected to the server, will wait for the user to enter a message. 


## Indication of exact format in which a user should enter each input

This message can consist of all ASCII characters, spaces, etc. An example can be seen in the example image, but another would be the phrase "This is a secret message." There is only one opportunity for the user to enter input each time the files are run. 


## Example image of the input and output when the program is run

![alt text](https://github.com/Cwagne17/NetSec_COSC450/tree/main/Assignment1/inputandoutput.png?raw=true)


## Method used to derive key K from S

ECDH Key Exchange - client creates key and sends it to server. The server then receives the client public key. Then the server generates a public key and sends it to client. Client and server then produce a derived key using the generated public keys. 
AES 256 bits key generation - Client and server produce secret keys based off the derived key generated in previous step.
AES-GCM - Client generates random 12 byte iv to use to encrypt/ decrypt message. Client encrypts plaintext using the secret key from previous step and iv. Client sends this message to server with the iv as a prefix. Server decrypts using secret key along with the iv. The process is completed, the plaintext has been encrypted, sent to the server, then decrypted to be returned to plaintext. 