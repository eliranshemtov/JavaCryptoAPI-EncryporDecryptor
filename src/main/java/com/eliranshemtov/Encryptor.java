package com.eliranshemtov;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;


public class Encryptor {
    private final KeysHandler keysHandler;
    private final String symmetricEncryptionAlgorithm;
    private final String symmetricTransformation;
    private final String asymmetricTransformationForKeyEncryption;
    private final String encryptedOutputPath;
    private final SignatureHandler signatureHandler;
    private final SecretKey secretKey;

    public Encryptor(KeysHandler keysHandler, String signatureAlgorithm, String symmetricEncryptionAlgorithm, String symmetricTransformation, String asymmetricTransformationForKeyEncryption, String encryptedOutputPath) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.keysHandler = keysHandler;
        this.symmetricEncryptionAlgorithm = symmetricEncryptionAlgorithm;
        this.symmetricTransformation = symmetricTransformation;
        this.asymmetricTransformationForKeyEncryption = asymmetricTransformationForKeyEncryption;
        this.encryptedOutputPath = encryptedOutputPath;
        this.signatureHandler = new SignatureHandler(keysHandler, signatureAlgorithm);
        this.secretKey = generateSymmetricSecretKey();
    }


    public void encrypt(String filepath) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, UnrecoverableKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = initCipherForEncryption(secretKey);
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
        FileHandler.updatePropsFile(this.signatureHandler.sign(filepath), RSAEncryptSymmetricSecretKey(), cipher.getIV());
    }


    private byte[] RSAEncryptSymmetricSecretKey () throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, KeyStoreException {
        PublicKey contactPublicKey = this.keysHandler.getContactPublic();
        Cipher cipher = Cipher.getInstance(asymmetricTransformationForKeyEncryption);;
        cipher.init(Cipher.ENCRYPT_MODE, contactPublicKey);
        return cipher.doFinal(this.secretKey.getEncoded());
    }

    private SecretKey generateSymmetricSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance(this.symmetricEncryptionAlgorithm);
        keygen.init(new SecureRandom());
        return keygen.generateKey();
    }

    private Cipher initCipherForEncryption(SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(symmetricTransformation);
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        return cipher;
    }
}
