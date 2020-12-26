package com.eliranshemtov;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;

public class Encryptor {
    public void encrypt(String filepath) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, UnrecoverableKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // Sanitize and get encrypted file name.
        String outputPath = "out.enc";
        String metaPath = "meta.properties";

        // generate digital signature and write the .meta file
        KeyStore ksA;
        ksA = KeyStore.getInstance("JKS");
        ksA.load(new FileInputStream("/Users/eliran.shemtov/.keystoreA.jks"), "eliran712".toCharArray());

        PrivateKey privateKey = (PrivateKey) ksA.getKey("aSide", "eliran712".toCharArray());
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);

        FileInputStream fis = new FileInputStream(filepath);
        BufferedInputStream bufin = new BufferedInputStream(fis);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = bufin.read(buffer)) >= 0) {
            sig.update(buffer, 0, len);
        };
        bufin.close();
        byte[] signatureBytes = sig.sign();


        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(new SecureRandom());
        SecretKey secretKey = keygen.generateKey();

        PublicKey recipientsPubKey = ksA.getCertificate("bSide").getPublicKey();
        byte[] encryptedSecretKey = RSAEncryptSymmetricSecretKey(recipientsPubKey, secretKey);

        Properties props = new Properties();
        props.setProperty("digitalSignature", Arrays.toString(signatureBytes));
        props.setProperty("EncryptedEncryptionKey", Arrays.toString(encryptedSecretKey));
        FileWriter fileWriter = new FileWriter(metaPath);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[cipher.getBlockSize()];
        randomSecureRandom.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

        props.setProperty("IV", Arrays.toString(iv));
        props.store(fileWriter, "Encryption details");
        fileWriter.close();

        try (InputStream inputStream = new FileInputStream("test.txt");
             OutputStream outputStream = new FileOutputStream("out.enc")) {
            try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                byte[] input = new byte[cipher.getBlockSize()];
                int bytesRead;

                while ((bytesRead = inputStream.read(input)) >= 0) {
                    cipherOutputStream.write(input, 0, bytesRead);
                }
            }
        }
    }


    private byte[] RSAEncryptSymmetricSecretKey (PublicKey recipientsPubKey, SecretKey secretKey)
    {
        Cipher cipher = null;
        byte[] key = null;
        try
        {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, recipientsPubKey);
            key = cipher.doFinal(secretKey.getEncoded());
        }
        catch(Exception e )
        {
            System.out.println ( "exception encoding key: " + e.getMessage() );
            e.printStackTrace();
        }
        return key;
    }
}
