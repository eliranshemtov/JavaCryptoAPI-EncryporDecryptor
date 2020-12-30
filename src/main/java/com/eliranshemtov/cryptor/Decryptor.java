package com.eliranshemtov.cryptor;

import com.eliranshemtov.App;
import com.eliranshemtov.services.FileService;
import com.eliranshemtov.services.KeysService;
import com.eliranshemtov.services.SignatureService;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;
import static com.eliranshemtov.control.Constants.*;


public class Decryptor implements Cryptor{
    private final KeysService keysService;
    private final SignatureService signatureService;
    private final Properties properties;
    private final String filePath;

    /**
     * Decryptor - implements the Cryptor interface. Main goal: load configuration file and according to it - verify digital signature of an encrypted file and decrypt it if the signature is valid.
     * @param keysService keys service to handle keystore related actions
     * @param filePath encrypted input file path
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public Decryptor(KeysService keysService, String filePath) throws Throwable {
        this.filePath = filePath;
        App.logger.info("Initializing Decryptor...");
        this.keysService = keysService;
        this.properties = FileService.loadDecryptionProps();
        this.signatureService = new SignatureService(keysService, this.properties.getProperty(SIGNATURE_ALG));
    }

    /**
     * Decrypt action
     * 1. initialize a cipher object
     * 2. read the digital signature from the config file
     * 3. get signature object, initialized for verification mode (with the contact's public key)
     * 4. open the encrypted file and read it by using a CipherInputStream (with the Cipher initialized in 1.)
     * 5. read from the CipherInputStream chunk by chunk, update the signature object with it and write it to the output file.
     * 6. at the EndOfFile, verify the signature read from the config file (with the signature object got in 3.)
     * 7. if the signature verification failed, an error message will be written to the output file and to the console.
     *
     * I read the required configurations from the config file, as the encryptor wrote them.
     * All of them are in cleartext, but the symmetric secret key, which we decrypt by using RSADecryptAESSymmetricKey() (with my private key)
     * With that symmetric secret key, the IV and the transformation name (which are also written in the config file) we generate a cipher, and initialize it for decryption.
     * That cipher is then given to the CipherInputStream that decrypts input stream on the run.
     * Every chunk we read is updated in the digital signature object. After we decrypt the entire file (and update the signature object with it),
     * We can use the retrieved signature object (which is initialized with the contact's public key)
     * to verify that the signature of the content we just fed it with is equal to the signature that the encryptor wrote to the config file.
     * if the signature verification fails we write an error message to the output file and throwing an exception (which will log an error to the console).
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public void action() throws Throwable {
        App.logger.info("Trying to decrypt the file '{}'...", this.filePath);
        Cipher cipher = initCipherForDecryption();
        byte[] digitalSignature = FileService.parsePropAsBytesArray(this.properties.getProperty(DIGITAL_SIGNATURE));
        Signature signatureVerifyObject = this.signatureService.getVerifySignatureObject();
        App.logger.info("Verifying Digital signature and decrypting...");
        try (InputStream is = new FileInputStream(this.filePath); OutputStream out = new FileOutputStream(DECRYPTED_OUTPUT_PATH)) {
            try (CipherInputStream cis = new CipherInputStream(is, cipher)) {
                byte[] input = new byte[cipher.getBlockSize()];
                int bytesRead;
                while ((bytesRead = cis.read(input)) >= 0) {
                    signatureVerifyObject.update(input, 0, bytesRead);
                    out.write(input, 0, bytesRead);
                }
            }
        }
        if (!signatureVerifyObject.verify(digitalSignature)) dealWithBadSignature();
        App.logger.info("Done decrypting! You may read your plaintext in '{}'", DECRYPTED_OUTPUT_PATH);
    }

    /**
     * Write "invalid signature error message" to the decrypted output file and throws and exception with the same message.
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private void dealWithBadSignature() throws Throwable{
        try(OutputStream out = new FileOutputStream(DECRYPTED_OUTPUT_PATH)){
            out.write(INVALID_SIG_ERR_MSG.getBytes());
        }
        throw new Exception(INVALID_SIG_ERR_MSG);
    }

    /**
     * RSADecryptAESSymmetricKey
     * 1. get the "my" private key
     * 2. read the Asymmetric transformation from config file
     * 3. initialize a cipher object with the transformation from (2) and with the private key from (1), for decrypt mode.
     * 4. get the symmetric encryption algorithm name from the config file
     * 5. decrypt the given encrypted symmetric key
     * 6. return a SecretKeySpec object, constructed with (5) and (4)
     * @param encryptedSymmetricKey - encrypted symmetric key as bytes array
     * @return SecretKeySpec object that was encrypted in the config file
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private SecretKey RSADecryptAESSymmetricKey(byte[] encryptedSymmetricKey) throws Throwable {
        App.logger.info("Decrypting the symmetric secret key from config file...");
        PrivateKey privateKey = this.keysService.getMyPrivate();
        Cipher cipher = Cipher.getInstance(this.properties.getProperty(ASYMMETRIC_TRANSFORMATION_FOR_KEY_ENCRYPTION));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new SecretKeySpec( cipher.doFinal(encryptedSymmetricKey), this.properties.getProperty(SYMMETRIC_ENCRYPTION_ALG));
    }

    /**
     * init Cipher object for decryption
     * 1. get the IV from the config file
     * 2. create an IV spec object
     * 3. get the encrypted symmetric encryption key from the config file, as byte array
     * 4. decrypt the encrypted symmetric encryption key from (3) using RSADecryptAESSymmetricKey()
     * 5. get the symmetric cipher transformation from config file.
     * 6. initialize a cipher object with (5), (4), (2)
     * @return initialized cipher object, ready for decryption.
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private Cipher initCipherForDecryption() throws Throwable {
        App.logger.info("Generating cipher object for decryption with '{}' transformation and the IV from config, with the decrypted symmetric secret key.", SYMMETRIC_CIPHER_TRANSFORMATION);
        byte[] ivBytes = FileService.parsePropAsBytesArray(this.properties.getProperty(IV));
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        byte[] encryptedEncryptionKey = FileService.parsePropAsBytesArray(this.properties.getProperty(ENCRYPTED_ENCRYPTION_KEY));
        SecretKey secretKey = RSADecryptAESSymmetricKey(encryptedEncryptionKey);
        Cipher cipher = Cipher.getInstance(this.properties.getProperty(SYMMETRIC_CIPHER_TRANSFORMATION));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return cipher;
    }
}
