package com.eliranshemtov;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;


public class App 
{
    public static final Logger logger = LoggerFactory.getLogger(App.class);
    public static void main( String[] args ) throws Exception {
    logger.info("Welcome to Eliran's Crypto App!");
        switch (args[0]){
            case "enc":
                encrypt(args[1]);
                break;
            case "dec":
                decrypt(args[1]);
                break;
            default:
                logger.error("Invalid parameters!");
                break;
        }
    }

    private static void encrypt(String filepath) {
        logger.info("Will try to encrypt the file: '{}'", filepath);
        try {
            KeysHandler keysHandler = new KeysHandler("/Users/eliran.shemtov/.keystoreA.jks", "eliran712");
            Encryptor encryptor = new Encryptor(keysHandler,"SHA256withRSA", "AES", "AES/CBC/PKCS5Padding", "RSA/ECB/PKCS1Padding", "out.enc");
            encryptor.encrypt("test.txt");
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | UnrecoverableKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    };

    private static void decrypt(String filepath) throws Exception {
        logger.info("Will try to decrypt the file: '{}'", filepath);
        try {
            KeysHandler keysHandler = new KeysHandler("/Users/eliran.shemtov/.keystoreB.jks", "eliran712");
            Decryptor decryptor = new Decryptor(keysHandler,"SHA256withRSA","AES/CBC/PKCS5Padding", "RSA/ECB/PKCS1Padding");
            decryptor.decrypt("out.enc");
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | UnrecoverableKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    };

}
