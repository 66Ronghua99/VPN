# VPN

- This VPN project consists of two most important part: ForwardClient, ForwardServer. Basically, The client start the forwardclient to establish a tunnel between the forwardclient and the forwardserver. In this initialization part, forwardclient and forwardserver would perform a handshake and exchange their certificates used later for the encryption of symmetric key. Then, forwardclient will inform the forwardserver the target port/host of the final server. After that, forwardserver will generate a 128 bytes AES key and send it to forwardclient using the publickey extracted from client's certificate to encrypt the initial value and the key in Base64 coding form. 
When the handshake is over, forwardclient would send a proxy host:port message for user. In this project we suggest use netcat to test the project. When the user connect to the specific host:port, the whole connection is initialized. 

We assume the network environments behind forwardclient and forwardserver are safe and all information between forwardclient and forwardserver are encrypted by AES key.
