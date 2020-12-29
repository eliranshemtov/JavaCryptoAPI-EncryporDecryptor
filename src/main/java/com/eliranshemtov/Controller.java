package com.eliranshemtov;

import org.apache.commons.cli.CommandLine;

public class Controller {
    private final CommandLine cmd;

    public Controller(CommandLine cmd){
        this.cmd = cmd;
    }

    public Cryptor getCryptor() throws Throwable {
        if (cmd.hasOption("encrypt")) {
            String inputFilePath = cmd.getOptionValue("inputFile", "plaintext.txt");
            String outPath = cmd.getOptionValue("outputEncryptedFile", "encrypted.enc");
            String keystore = cmd.getOptionValue("keystoreFile", "/Users/eliran.shemtov/.keystoreA.jks");
            String myAlias = cmd.getOptionValue("myAlias", "alice");
            String contactAlias = cmd.getOptionValue("contactAlias", "bob");
            String signatureAlg = cmd.getOptionValue("signatureAlg", "SHA256withRSA");
            String symmetricEncryptionAlg = cmd.getOptionValue("symEncAlg", "AES");
            String symmetricTransformation = cmd.getOptionValue("symTrans", "AES/CBC/PKCS5Padding");
            String asymmetricTransformation = cmd.getOptionValue("aSymTrans", "RSA/ECB/PKCS1Padding");
            String password = getPassword(cmd);
            KeysHandler keysHandler = new KeysHandler(keystore, password, myAlias, contactAlias);
            return new Encryptor(keysHandler, signatureAlg, symmetricEncryptionAlg, symmetricTransformation, asymmetricTransformation, inputFilePath, outPath);
        } else if (cmd.hasOption("decrypt")) {
            String keystore = cmd.getOptionValue("keystoreFile", "/Users/eliran.shemtov/.keystoreB.jks");
            String myAlias = cmd.getOptionValue("myAlias", "bob");
            String contactAlias = cmd.getOptionValue("contactAlias", "alice");
            String filePath = cmd.getOptionValue("inputFile", "encrypted.enc");
            String password = getPassword(cmd);
            KeysHandler keysHandler = new KeysHandler(keystore, password, myAlias, contactAlias);
            return new Decryptor(keysHandler, filePath);
        } else {
            throw new Exception("No Operation mode was chosen");
        }
    };

    private static String getPassword(CommandLine cmd) throws Exception {
        String password = cmd.getOptionValue("keystorePassword");
        if (password == null){
            throw new Exception("Missing password for keystore");
        }
        return password;
    }
}


