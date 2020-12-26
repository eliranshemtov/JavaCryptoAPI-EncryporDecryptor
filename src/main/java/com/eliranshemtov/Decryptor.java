package com.eliranshemtov;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Properties;

public class Decryptor {
    public void decrypt(String filepath) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableKeyException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, SignatureException {
        String metaPath = "meta.properties";
        File configFile = new File(metaPath);
        FileReader fileReader = new FileReader(configFile);
        Properties props = new Properties();
        props.load(fileReader);
        String digitalSignature = props.getProperty("digitalSignature");
        String encryptedEncryptionKey =  props.getProperty("EncryptedEncryptionKey");
        String iv =  props.getProperty("IV");
        fileReader.close();

// to verify signature
        KeyStore ksB;
        ksB = KeyStore.getInstance("JKS");
        ksB.load(new FileInputStream("/Users/eliran.shemtov/.keystoreB.jks"), "eliran712".toCharArray());
//        PublicKey publicKey = ksB.getCertificate("aSide").getPublicKey();
//        Signature sig = Signature.getInstance("SHA256withRSA");
//        sig.initVerify(publicKey);
//        sig.update(data);
//        Boolean result = sig.verify(signatureBytes);
        PrivateKey privateKey = (PrivateKey) ksB.getKey("bSide", "eliran712".toCharArray());


        String[] byteValues = iv.substring(1, iv.length() - 1).split(",");
        byte[] bytes = new byte[byteValues.length];

        for (int i=0, len=bytes.length; i<len; i++) {
            bytes[i] = Byte.parseByte(byteValues[i].trim());
        }




        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(bytes);


        String[] byteValues2 = encryptedEncryptionKey.substring(1, encryptedEncryptionKey.length() - 1).split(",");
        byte[] encryptedEncryptionKey2 = new byte[byteValues2.length];

        for (int i=0, len=encryptedEncryptionKey2.length; i<len; i++) {
            encryptedEncryptionKey2[i] = Byte.parseByte(byteValues2[i].trim());
        }

        SecretKey secretKey = RSADecryptAESSymmetricKey(privateKey, encryptedEncryptionKey2);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        String srcFile = "out.enc";
        String destFile = "out.dec";
        try (InputStream is = new FileInputStream(srcFile); OutputStream out = new FileOutputStream(destFile)) {
            try (CipherInputStream cis = new CipherInputStream(is, cipher)) {
                byte[] input = new byte[cipher.getBlockSize()];
                int bytesRead;

                while ((bytesRead = cis.read(input)) >= 0) {
                    out.write(input, 0, bytesRead);
                }
            }
        };

        PublicKey sendersPubKey = ksB.getCertificate("aSide").getPublicKey();
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(sendersPubKey);

        String[] sigStrArray = digitalSignature.substring(1, digitalSignature.length() - 1).split(",");
        byte[] sigBytesArray = new byte[sigStrArray.length];

        for (int i=0, len=sigBytesArray.length; i<len; i++) {
            sigBytesArray[i] = Byte.parseByte(sigStrArray[i].trim());
        }

        try (InputStream inputStream = new FileInputStream(destFile)){
            byte[] input = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(input)) >= 0) {
                sig.update(input, 0, bytesRead);
            }
        }
        Boolean result = sig.verify(sigBytesArray);
        App.logger.info("RES: {}", result);


    }

    private SecretKey RSADecryptAESSymmetricKey(PrivateKey privateKey, byte[] encryptedSymmetricKey) {
        SecretKey key = null;
        Cipher cipher = null;
        try
        {
            // initialize the cipher...
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            key = new SecretKeySpec( cipher.doFinal(encryptedSymmetricKey), "AES" );
        }
        catch(Exception e)
        {
            System.out.println ( "exception decrypting the aes key: "
                    + e.getMessage() );
            return null;
        }

        return key;
    }
}
