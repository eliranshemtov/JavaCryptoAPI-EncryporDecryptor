package com.eliranshemtov.cryptor;

import com.eliranshemtov.App;
import com.eliranshemtov.services.FileService;
import com.eliranshemtov.services.KeysService;
import com.eliranshemtov.services.SignatureService;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import static com.eliranshemtov.control.Constants.META_PATH;


public class Encryptor implements Cryptor{
    private final KeysService keysService;
    private final String symmetricEncryptionAlgorithm;
    private final String symmetricTransformation;
    private final String asymmetricTransformationForKeyEncryption;
    private final String encryptedOutputPath;
    private final SignatureService signatureService;
    private final SecretKey secretKey;
    private final String signatureAlgorithm;
    private final String inputFilePath;

    /**
     * Encryptor - implements the Cryptor interface. Main goal: receive parameters and according to it - encrypt a given file and set the required parameters for decryption in a config file.
     * This constructor also generates the symmetric secret key and the signature service.
     * @param keysService - initialized KeysService to perform keystore actions and retrieve keys
     * @param signatureAlgorithm - algorithm to be used when digitally sign the encrypted file
     * @param symmetricEncryptionAlgorithm - symmetric encryption algorithm. to be used for secret generation.
     * @param symmetricTransformation - symmetric transformation. to be used generating the encryption cipher
     * @param asymmetricTransformationForKeyEncryption - the Asymmetric transformation bo be used when encrypting the symmetric key.
     * @param inputFilePath - the path of input file to be encrypted
     * @param encryptedOutputPath - the path of the encrypted output file.
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public Encryptor(KeysService keysService, String signatureAlgorithm, String symmetricEncryptionAlgorithm, String symmetricTransformation, String asymmetricTransformationForKeyEncryption, String inputFilePath, String encryptedOutputPath) throws Throwable{
        App.logger.info("Initializing Encryptor...");
        this.inputFilePath = inputFilePath;
        this.keysService = keysService;
        this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
        this.symmetricTransformation = symmetricTransformation;
        this.asymmetricTransformationForKeyEncryption = asymmetricTransformationForKeyEncryption;
        this.encryptedOutputPath = encryptedOutputPath;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureService = new SignatureService(keysService, signatureAlgorithm);
        this.secretKey = generateSymmetricSecretKey();
    }

    /**
     * Encrypt action
     * 1. get cipher object, ready for encryption
     * 2. open the input plaintext file and encrypt it using a CipherOutputStream
     * 3. iterate over the CipherOutputStream, chunk by chunk, and write it (encrypted) to the output file
     * 4. digitally sign the input file's content
     * 5. encrypt the symmetric secret key
     * 6. write (4), (5), the IV, and algorithms / transformations into a config file, so that the decryptor could use them while decrypting.
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public void action() throws Throwable {
        App.logger.info("Encrypting the file in '{}'", this.inputFilePath);
        Cipher cipher = initCipherForEncryption(this.secretKey);
        try (InputStream inputStream = new FileInputStream(this.inputFilePath);
             OutputStream outputStream = new FileOutputStream(this.encryptedOutputPath)) {
            try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                byte[] input = new byte[cipher.getBlockSize()];
                int bytesRead;
                while ((bytesRead = inputStream.read(input)) >= 0) {
                    cipherOutputStream.write(input, 0, bytesRead);
                }
            }
        }
        FileService.updatePropsFile(this.signatureService.sign(this.inputFilePath), RSAEncryptSymmetricSecretKey(), cipher.getIV(), this.symmetricEncryptionAlgorithm, this.asymmetricTransformationForKeyEncryption, this.symmetricTransformation, this.signatureAlgorithm);
        App.logger.info("Done encrypting your file! You may send both '{}' and '{}' to your contact", this.encryptedOutputPath, META_PATH);
    }

    /**
     * RSAEncryptSymmetricSecretKey - encrypting the Symmetric secret key with RSA Algorithm
     * 1. get the contacts public key
     * 2. initialize a cipher with this.asymmetricTransformationForKeyEncryption and the contact's public key, for encryption mode
     * 3. encrypt the secret key and return it as byte array.
     * @return
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private byte[] RSAEncryptSymmetricSecretKey () throws Throwable {
        App.logger.info("Encrypting the symmetric key with '{}' transformation, using the contact's public key", this.asymmetricTransformationForKeyEncryption);
        PublicKey contactPublicKey = this.keysService.getContactPublic();
        Cipher cipher = Cipher.getInstance(this.asymmetricTransformationForKeyEncryption);
        cipher.init(Cipher.ENCRYPT_MODE, contactPublicKey);
        return cipher.doFinal(this.secretKey.getEncoded());
    }

    /**
     * Generate a SecretKey for the algorithm in this.symmetricEncryptionAlgorithm
     * @return SecretKey for the algorithm in this.symmetricEncryptionAlgorithm
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private SecretKey generateSymmetricSecretKey() throws Throwable {
        App.logger.info("Generating symmetric secret key using '{}' algorithm", this.symmetricEncryptionAlgorithm);
        KeyGenerator keygen = KeyGenerator.getInstance(this.symmetricEncryptionAlgorithm);
        keygen.init(new SecureRandom());
        return keygen.generateKey();
    }

    /**
     * initCipherForEncryption
     * 1. gets a secret key
     * 2. get instance of a cipher object that implements the transformation this.symmetricTransformation
     * 3. selects a random IV in a size of the cipher's block-size
     * 4. initialize the cipher object with the given secret key and the IV, for encryption mode.
     * 5. return the cipher
     * @param secretKey Secret key that was pre-generated
     * @return Cipher object, ready for encryption, initialized with secret key and IV, implements the transformation in this.symmetricTransformation.
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private Cipher initCipherForEncryption(SecretKey secretKey) throws Throwable {
        App.logger.info("Generating cipher object for encryption with '{}' transformation and random IV, with the symmetric secret key.", this.symmetricTransformation);
        Cipher cipher = Cipher.getInstance(this.symmetricTransformation);
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher;
    }
}
