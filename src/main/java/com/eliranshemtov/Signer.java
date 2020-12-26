package com.eliranshemtov;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.swing.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;


public class Signer {
    private KeyStore ks;
    private KeyStore ks2;
    public Signer(String keystorePath, char [] keystorePass){
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(keystorePath), keystorePass);

            ks2 = KeyStore.getInstance("JKS");
            ks2.load(new FileInputStream("/Users/eliran.shemtov/.keystoreB"), "eliran712".toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
    }



    public byte[] sign(byte[] data) throws NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, CertificateException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        byte[] test = "test".getBytes(StandardCharsets.UTF_8);
        PrivateKey privateKey = (PrivateKey) ks.getKey("aSide", "eliran712".toCharArray());
        Signature dsa = Signature.getInstance("SHA256withDSA", "SUN");
        dsa.initSign(privateKey);
        dsa.update(test);
        byte[] signatureBytes = dsa.sign();
        PublicKey publicKey = ks.getCertificate("aSide").getPublicKey();
        dsa.initVerify(publicKey);
        dsa.update(test);
        Boolean result = dsa.verify(signatureBytes);
        App.logger.info("This is the result: {}", result);

        return new byte[2];

//        FileInputStream fis = new FileInputStream("/Users/eliran.shemtov/OneDrive/OneDrive/Master degree/Big data analysis/spark_analytics_exercises/Exercise 3/data/movie_scripts/Angelina Jolie_Taking Lives.txt");
//        BufferedInputStream bufin = new BufferedInputStream(fis);
//        byte[] buffer = new byte[1024];
//        int len;
//        while ((len = bufin.read(buffer)) >= 0) {
//            try {
//                dsa.update(buffer, 0, len);
//            } catch (SignatureException e) {
//                e.printStackTrace();
//            }
//        };
//        bufin.close();

//        Signature dsa = Signature.getInstance("SHA256withDSA");
//        PrivateKey privateKey = (PrivateKey) ks.getKey("aSide", "eliran712".toCharArray());
//        PublicKey publicKey = ks2.getCertificate("aSide").getPublicKey();
//        Signature dsa2 = Signature.getInstance("SHA256withDSA");
//        byte[] fileSignature = new byte[0];
//        try {
//            dsa.initSign(privateKey);
//            dsa.update(data);
//            fileSignature = dsa.sign();
//            dsa2.initVerify(publicKey);
//            Boolean result = dsa2.verify(fileSignature);
//            App.logger.info("RESULT: {}", result);
//        } catch (InvalidKeyException | SignatureException e) {
//            e.printStackTrace();
//        }
//        return fileSignature;
    }
}
