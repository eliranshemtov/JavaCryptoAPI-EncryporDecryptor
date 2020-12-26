package com.eliranshemtov;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.util.Properties;

import static com.eliranshemtov.Constants.*;

public class Decryptor {
    private final KeysHandler keysHandler;;
    private final String symmetricTransformation;
    private final String asymmetricTransformationForKeyEncryption;
    private final SignatureHandler signatureHandler;
    private final Properties properties;

    public Decryptor(KeysHandler keysHandler, String signatureAlgorithm, String symmetricTransformation, String asymmetricTransformationForKeyEncryption) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException {
        this.keysHandler = keysHandler;
        this.symmetricTransformation = symmetricTransformation;
        this.asymmetricTransformationForKeyEncryption = asymmetricTransformationForKeyEncryption;
        this.signatureHandler = new SignatureHandler(keysHandler, signatureAlgorithm);
        this.properties = FileHandler.loadDecryptionProps();
    }

    public void decrypt(String filepath) throws Exception {
        Cipher cipher = initCipherForDecryption();
        byte[] digitalSignature = FileHandler.parsePropAsBytesArray(this.properties.getProperty(DIGITAL_SIGNATURE));
        Boolean isSignatureValid = this.signatureHandler.verifySignature(filepath, digitalSignature, cipher);
        if (isSignatureValid) {
            String decryptedFile = "decrypted.txt";
            try (InputStream is = new FileInputStream(filepath); OutputStream out = new FileOutputStream(decryptedFile)) {
                try (CipherInputStream cis = new CipherInputStream(is, cipher)) {
                    byte[] input = new byte[cipher.getBlockSize()];
                    int bytesRead;
                    while ((bytesRead = cis.read(input)) >= 0) {
                        out.write(input, 0, bytesRead);
                    }
                };
            }
        } else {
            throw new Exception("Digital Signature is invalid!");
        }
    }

    private SecretKey RSADecryptAESSymmetricKey(byte[] encryptedSymmetricKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException {
        PrivateKey privateKey = this.keysHandler.getMyPrivate();
        Cipher cipher = Cipher.getInstance(this.asymmetricTransformationForKeyEncryption);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new SecretKeySpec( cipher.doFinal(encryptedSymmetricKey), "AES" );
    }

    private Cipher initCipherForDecryption() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, UnrecoverableKeyException, KeyStoreException, InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] ivBytes = FileHandler.parsePropAsBytesArray(this.properties.getProperty(IV));
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        byte[] encryptedEncryptionKey = FileHandler.parsePropAsBytesArray(this.properties.getProperty(ENCRYPTED_ENCRYPTION_KEY));
        Cipher cipher = Cipher.getInstance(symmetricTransformation);
        SecretKey secretKey = RSADecryptAESSymmetricKey(encryptedEncryptionKey);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        return cipher;
    }
}
