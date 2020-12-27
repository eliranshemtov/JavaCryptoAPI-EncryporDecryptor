package com.eliranshemtov;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

import static com.eliranshemtov.Constants.META_PATH;


public class Encryptor {
    private final KeysHandler keysHandler;
    private final String symmetricEncryptionAlgorithm;
    private final String symmetricTransformation;
    private final String asymmetricTransformationForKeyEncryption;
    private final String encryptedOutputPath;
    private final SignatureHandler signatureHandler;
    private final SecretKey secretKey;
    private final String signatureAlgorithm;

    public Encryptor(KeysHandler keysHandler, String signatureAlgorithm, String symmetricEncryptionAlgorithm, String symmetricTransformation, String asymmetricTransformationForKeyEncryption, String encryptedOutputPath) throws NoSuchAlgorithmException{
        App.logger.info("Initializing Encryptor...");
        this.keysHandler = keysHandler;
        this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
        this.symmetricTransformation = symmetricTransformation;
        this.asymmetricTransformationForKeyEncryption = asymmetricTransformationForKeyEncryption;
        this.encryptedOutputPath = encryptedOutputPath;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureHandler = new SignatureHandler(keysHandler, signatureAlgorithm);
        this.secretKey = generateSymmetricSecretKey();
    }

    public void encrypt(String filepath) throws IOException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnrecoverableKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        App.logger.info("Encrypting the file in '{}'", filepath);
        Cipher cipher = initCipherForEncryption(this.secretKey);
        try (InputStream inputStream = new FileInputStream(filepath);
             OutputStream outputStream = new FileOutputStream(this.encryptedOutputPath)) {
            try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                byte[] input = new byte[cipher.getBlockSize()];
                int bytesRead;
                while ((bytesRead = inputStream.read(input)) >= 0) {
                    cipherOutputStream.write(input, 0, bytesRead);
                }
            }
        }
        FileHandler.updatePropsFile(this.signatureHandler.sign(filepath), RSAEncryptSymmetricSecretKey(), cipher.getIV(), this.symmetricEncryptionAlgorithm, this.asymmetricTransformationForKeyEncryption, this.symmetricTransformation, this.signatureAlgorithm);
        App.logger.info("Done encrypting your file! You may send both '{}' and '{}' to your contact", this.encryptedOutputPath, META_PATH);
    }

    private byte[] RSAEncryptSymmetricSecretKey () throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, KeyStoreException {
        App.logger.info("Encrypting the symmetric key with '{}' transformation, using the contact's public key", this.asymmetricTransformationForKeyEncryption);
        PublicKey contactPublicKey = this.keysHandler.getContactPublic();
        Cipher cipher = Cipher.getInstance(this.asymmetricTransformationForKeyEncryption);
        cipher.init(Cipher.ENCRYPT_MODE, contactPublicKey);
        return cipher.doFinal(this.secretKey.getEncoded());
    }

    private SecretKey generateSymmetricSecretKey() throws NoSuchAlgorithmException {
        App.logger.info("Generating symmetric secret key using '{}' algorithm", this.symmetricEncryptionAlgorithm);
        KeyGenerator keygen = KeyGenerator.getInstance(this.symmetricEncryptionAlgorithm);
        keygen.init(new SecureRandom());
        return keygen.generateKey();
    }

    private Cipher initCipherForEncryption(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
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
