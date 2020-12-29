package com.eliranshemtov;

import org.apache.commons.cli.*;

public class ArgsParser {
    public CommandLine parse( String[] args ) throws Throwable {
        Options options = new Options();
        options.addOption("h", "help", false, "List the command line arguments this app receives");
        options.addOption("e", "encrypt", false, "*** Mode: Encryption mode");
        options.addOption("d", "decrypt", false, "*** Mode: Decryption mode");
        options.addOption("p", "keystorePassword", true, "*** Password to the keystore");
        options.addOption("inf", "inputFile", true, "Input file (Encryption default: plaintext.txt | Decryption default: encrypted.enc)");
        options.addOption("ouf", "outputEncryptedFile", true, "[Encryption only] Output file for encrypted result (default: encrypted.enc");
        options.addOption("k", "keystoreFile", true, "Keystore file to use (default: /Users/eliran.shemtov/.keystoreA.jks)");
        options.addOption("mal", "myAlias", true, "My key's alias in the keystore (Encryption default: alice | Decryption default: bob)");
        options.addOption("mca", "contactAlias", true, "Contact cert alias in the keystore (Encryption default: bob | Decryption default: alice)");
        options.addOption("sa", "signatureAlg", true, "[Encryption only] Algorithm to be used for digital signature (default: SHA256withRSA)");
        options.addOption("sea", "symEncAlg", true, "[Encryption only] Algorithm to be used for symmetric encryption (default: AES)");
        options.addOption("st", "symTrans", true, "[Encryption only] Transformation to be used for symmetric encryption (default: AES/CBC/PKCS5Padding)");
        options.addOption("ast", "aSymTrans", true, "[Encryption only] Transformation to be used for Asymmetric encryption of the symmetric key (default: RSA/ECB/PKCS1Padding)");
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args);
        if (!cmd.hasOption("encrypt") && !cmd.hasOption("decrypt") || cmd.hasOption("help")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("Eliran's Crypto App", options);
            throw new Exception("Invalid arguments, Please refer this documentation.");
        }
        return cmd;
    }
}
