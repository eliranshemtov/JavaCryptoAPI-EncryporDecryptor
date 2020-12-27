package com.eliranshemtov;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;
import static com.eliranshemtov.Constants.*;

public class Decryptor {
    private final KeysHandler keysHandler;
    private final SignatureHandler signatureHandler;
    private final Properties properties;

    public Decryptor(KeysHandler keysHandler) throws NoSuchAlgorithmException, IOException {
        App.logger.info("Initializing Decryptor...");
        this.keysHandler = keysHandler;
        this.properties = FileHandler.loadDecryptionProps();
        this.signatureHandler = new SignatureHandler(keysHandler, this.properties.getProperty(SIGNATURE_ALG));
    }

    public void decrypt(String filepath) throws Exception {
        App.logger.info("Trying to decrypt the file '{}'...", filepath);
        Cipher cipher = initCipherForDecryption();
        byte[] digitalSignature = FileHandler.parsePropAsBytesArray(this.properties.getProperty(DIGITAL_SIGNATURE));
        Boolean isSignatureValid = this.signatureHandler.verifySignature(filepath, digitalSignature, cipher);
        if (isSignatureValid) {
            App.logger.info("Digital signature of the file is complete, will decrypt the file into '{}'", DECRYPTED_OUTPUT_PATH);
            try (InputStream is = new FileInputStream(filepath); OutputStream out = new FileOutputStream(DECRYPTED_OUTPUT_PATH)) {
                try (CipherInputStream cis = new CipherInputStream(is, cipher)) {
                    byte[] input = new byte[cipher.getBlockSize()];
                    int bytesRead;
                    while ((bytesRead = cis.read(input)) >= 0) {
                        out.write(input, 0, bytesRead);
                    }
                }
            }
        } else {
            try(OutputStream out = new FileOutputStream(DECRYPTED_OUTPUT_PATH)){
                out.write(INVALID_SIG_ERR_MSG.getBytes());
            }
            throw new Exception(INVALID_SIG_ERR_MSG);
        }
        App.logger.info("Done decrypting! You may read your plaintext in '{}'", DECRYPTED_OUTPUT_PATH);
    }

    private SecretKey RSADecryptAESSymmetricKey(byte[] encryptedSymmetricKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        App.logger.info("Decrypting the symmetric secret key from config file...");
        PrivateKey privateKey = this.keysHandler.getMyPrivate();
        Cipher cipher = Cipher.getInstance(this.properties.getProperty(ASYMMETRIC_TRANSFORMATION_FOR_KEY_ENCRYPTION));
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new SecretKeySpec( cipher.doFinal(encryptedSymmetricKey), this.properties.getProperty(SYMMETRIC_ENCRYPTION_ALG));
    }

    private Cipher initCipherForDecryption() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, InvalidAlgorithmParameterException {
        App.logger.info("Generating cipher object for decryption with '{}' transformation and the IV from config, with the decrypted symmetric secret key.", SYMMETRIC_CIPHER_TRANSFORMATION);
        byte[] ivBytes = FileHandler.parsePropAsBytesArray(this.properties.getProperty(IV));
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        byte[] encryptedEncryptionKey = FileHandler.parsePropAsBytesArray(this.properties.getProperty(ENCRYPTED_ENCRYPTION_KEY));
        Cipher cipher = Cipher.getInstance(this.properties.getProperty(SYMMETRIC_CIPHER_TRANSFORMATION));
        SecretKey secretKey = RSADecryptAESSymmetricKey(encryptedEncryptionKey);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return cipher;
    }
}
