# Java Crypto API
## Building Secured applications (Masters degree course) - Exercise 2
 
 By: Eliran Shem Tov
 

### Encryption
 I generated a symmetric secret key. it is used for generating the Cipher, along with randomly chosen IV.
 this cipher is being used to create the cipherOutputStream. by reading the file using the cipherOutputStream, the chunks read are encrypted and written to the output file as required.
 Then I create a digital signature of the file's content using the signatureService.sign() method (which reads the file as cleartext and generates the signature, using my private key)
 Then I encrypt the symmetric secret key (RSA), with the contact's public key. so only he will be able to decrypt it using his private key.
 Both the signature, and the encrypted secret key, along with the IV and algorithms/transformations are written to the config file.
 There is no concern in writing them like this to the config file, as non of them but the secret key is confidential (and the secret key is encrypted).
 
 
 ### Decryption 
 I read the required configurations from the config file, as the encryptor wrote them.
 All of them are in cleartext, but the symmetric secret key, which we decrypt by using RSADecryptAESSymmetricKey() (with my private key)
 With that symmetric secret key, the IV and the transformation name (which are also written in the config file) we generate a cipher, and initialize it for decryption.
 That cipher is then given to the CipherInputStream that decrypts input stream on the run.
 Every chunk we read is updated in the digital signature object. After we decrypt the entire file (and update the signature object with it),
 We can use the retrieved signature object (which is initialized with the contact's public key)
 to verify that the signature of the content we just fed it with is equal to the signature that the encryptor wrote to the config file.
 if the signature verification fails we write an error message to the output file and throwing an exception (which will log an error to the console).
 
 
 #### usage: Eliran's Crypto App
```
 -h,--help                          List the command line arguments this app receives
 -d,--decrypt                       *** Mode: Decryption mode
 -e,--encrypt                       *** Mode: Encryption mode
 -p,--keystorePassword <arg>        *** Password to the keystore
 -k,--keystoreFile <arg>            Keystore file to use (default for encrypt: keystores/.keystoreA.jks, default for decrypt: keystores/.keystoreB.jks)
 -inf,--inputFile <arg>             Input file (Encryption default: plaintext.txt | Decryption default: encrypted.enc)
 -mal,--myAlias <arg>               My key's alias in the keystore (Encryption default: alice | Decryption default: bob)
 -mca,--contactAlias <arg>          Contact cert alias in the keystore (Encryption default: bob | Decryption default: alice)
 -ouf,--outputEncryptedFile <arg>   [Encryption only] Output file for encrypted result (default: encrypted.enc)
 -sa,--signatureAlg <arg>           [Encryption only] Algorithm to be used for digital signature (default: SHA256withRSA)
 -sea,--symEncAlg <arg>             [Encryption only] Algorithm to be used for symmetric encryption (default: AES)
 -st,--symTrans <arg>               [Encryption only] Transformation to be used for symmetric encryption(default: AES/CBC/PKCS5Padding)
 -ast,--aSymTrans <arg>             [Encryption only] Transformation to be used for Asymmetric encryption of the symmetric key (default:RSA/ECB/PKCS1Padding)
```

## Keystores and keys:
#### Generate keystores with keypairs for alice and bob:
> keytool -genkeypair -alias alice -keyalg RSA  -keystore .keystoreA.jks -storepass "fY+P#wEP645H@xuc?g?4" -dname "CN=Alice, OU=MTA, O=MSC, L=Tel Aviv, ST=TLV, C=IL"

> keytool -genkeypair -alias bob -keyalg RSA  -keystore .keystoreB.jks -storepass "#7fv*kfSB;/}Bfd'fS5ZL4" -dname "CN=Bob, OU=MTA, O=MSC, L=Tel Aviv, ST=TLV, C=IL"

#### Exporting certificates
> keytool -exportcert -alias alice -keystore .keystoreA.jks -file a.cert -storepass "fY+P#wEP645H@xuc?g?4"

>keytool -exportcert -alias bob -keystore .keystoreB.jks -file b.cert -storepass "#7fv*kfSB;/}Bfd'fS5ZL4"

#### Importing contact's certificate
> keytool -importcert -alias bob -keystore .keystoreA.jks -file b.cert -storepass "fY+P#wEP645H@xuc?g?4"

> keytool -importcert -alias alice -keystore .keystoreB.jks -file a.cert -storepass "#7fv*kfSB;/}Bfd'fS5ZL4"
