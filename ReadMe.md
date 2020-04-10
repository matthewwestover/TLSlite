## TLSlite Assignment
There is some set up for this to work. First certificates and keys need to be generated for the client and server

### Certificate and Keys
This mainly uses the commandline openssl command to work. Place files in the respective folders within ```TLSlite/src/resources``` 

1) Generate a RSA Public/Private key pair for the "Certificate Authority":
```openssl req -x509 -newkey rsa:4096 -keyout CAprivateKey.pem -out CAcertificate.pem -days 30 -nodes```

2) Generate client/server keys + "certificate signature requests":
```openssl req -new -newkey rsa:4096 -nodes -keyout serverPrivate.key -out server.csr```
```openssl req -new -newkey rsa:4096 -nodes -keyout clientPrivate.key -out client.csr```

3) Use the config.cnf file for this next step:

```
mkdir certs newcerts
touch index.txt
echo 1000 > serial
```

```openssl ca -config config.cnf -cert CAcertificate.pem -keyfile CAprivateKey.pem -in server.csr -out CASignedServerCertificate.pem```
```openssl ca -config config.cnf -cert CAcertificate.pem -keyfile CAprivateKey.pem -in client.csr -out CASignedClientCertificate.pem```

4) To change the key file formats to something more Java/User friendly:
```openssl pkcs8 -topk8 -outform DER -in serverPrivate.key -out serverPrivateKey.der -nocrypt```
```openssl pkcs8 -topk8 -outform DER -in clientPrivate.key -out clientPrivateKey.der -nocrypt```

With this commands done:
1) Place CAcertificate.pem, CASignedClientCertificate.pem, CASignedServerCertificate.pem in ```TLSlite/src/resources/certs```.  
2) Place clientPrivateKey.der, serverPrivateKey.der in ```TLSlite/src/recourses/keys```.

### Compile
With the certificates and keys in the right location in the command line navigate to ```src/client``` and to ```src/server```. 
In both folders via the command line run:
```javac *.java```

In two seperate commandline windows navigate to the ```TLSlite/src``` folder.
In one run the command: ```java server.Server``` this will open the server and keep it open listening for a client.  
In the other run: ```java client.Client``` this will open up a client for the handshake and file transfer. 

Transferred files can be seen in the ```TLSlite/src/resources``` folder. 

