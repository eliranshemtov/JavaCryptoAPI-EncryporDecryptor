package com.eliranshemtov.control;

import com.eliranshemtov.cryptor.Cryptor;
import com.eliranshemtov.cryptor.Decryptor;
import com.eliranshemtov.cryptor.Encryptor;
import com.eliranshemtov.services.KeysService;
import org.apache.commons.cli.CommandLine;


public class Controller {
    private final CommandLine cmd;

    /**
     * In order to avoid logic in the main function as much as possible, decision making according to received args was
     * extracted to the controller
     * @param cmd Apache.commons.cli.CommandLine object that allows easy parameter extraction.
     */
    public Controller(CommandLine cmd){
        this.cmd = cmd;
    }

    /**
     * getCryptor extracts the parsed parameters that were given to the app. Then it constructs a Crypto object (Encryptor/Decryptor)
     * according to the parameters, and returns it ready for action.
     * @return
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
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
            KeysService keysService = new KeysService(keystore, password, myAlias, contactAlias);
            return new Encryptor(keysService, signatureAlg, symmetricEncryptionAlg, symmetricTransformation, asymmetricTransformation, inputFilePath, outPath);
        } else if (cmd.hasOption("decrypt")) {
            String keystore = cmd.getOptionValue("keystoreFile", "/Users/eliran.shemtov/.keystoreB.jks");
            String myAlias = cmd.getOptionValue("myAlias", "bob");
            String contactAlias = cmd.getOptionValue("contactAlias", "alice");
            String filePath = cmd.getOptionValue("inputFile", "encrypted.enc");
            String password = getPassword(cmd);
            KeysService keysService = new KeysService(keystore, password, myAlias, contactAlias);
            return new Decryptor(keysService, filePath);
        } else {
            throw new Exception("No Operation mode was chosen");
        }
    };

    /**
     * Mini helper function that verifies that a password was among the command line arguments. if was not present, throws and execption.
     * @param cmd Apache.commons.cli.CommandLine object that allows easy parameter extraction.
     * @return password as a String
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    private static String getPassword(CommandLine cmd) throws Throwable {
        String password = cmd.getOptionValue("keystorePassword");
        if (password == null){
            throw new Exception("Missing password for keystore");
        }
        return password;
    }
}


