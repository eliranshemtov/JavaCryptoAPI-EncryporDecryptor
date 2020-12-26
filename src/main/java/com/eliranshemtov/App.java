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
    public static void main( String[] args ) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, UnrecoverableKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
        logger.info("Welcome to Eliran's Crypto App!");
//        if (args.length == 2){
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
//        } else {
//            logger.error("You must supply method and filepath");
//        }
    }

    private static void encrypt(String filepath) {
        logger.info("Will try to encrypt the file: '{}'", filepath);
        try {
            new Encryptor().encrypt(filepath);
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | UnrecoverableKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    };

    private static void decrypt(String filepath) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, BadPaddingException, UnrecoverableKeyException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {
        logger.info("Will try to decrypt the file: '{}'", filepath);
        new Decryptor().decrypt(filepath);
    };

}
