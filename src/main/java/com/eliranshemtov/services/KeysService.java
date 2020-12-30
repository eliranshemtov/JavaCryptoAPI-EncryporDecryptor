package com.eliranshemtov.services;

import com.eliranshemtov.App;
import java.io.FileInputStream;
import java.security.*;


public class KeysService {
    private final char[] keystorePass;
    private final String myAlias;
    private final String contactAlias;
    private final KeyStore ks;

    /**
     * KeysService is the KeyStore handler, fetches keys for you.
     * @param keystoreFilePath file path of a JKS KeyStore
     * @param keystorePass password for the KeyStore
     * @param myAlias the alias for MY keys in the KeyStore
     * @param contactAlias the alias for the contact's certificate and public key
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public KeysService(String keystoreFilePath, String keystorePass, String myAlias, String contactAlias) throws Throwable {
        App.logger.info("Initializing KeysHandler for keystore: '{}' where my key's alias is '{}' and my contact's is '{}'", keystoreFilePath, myAlias, contactAlias);
        this.keystorePass = keystorePass.toCharArray();
        this.myAlias = myAlias;
        this.contactAlias = contactAlias;
        this.ks = KeyStore.getInstance("JKS");
        this.ks.load(new FileInputStream(keystoreFilePath), this.keystorePass);
    }

    /**
     * Get the private key with MY alias
     * @return PrivateKey
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public PrivateKey getMyPrivate() throws Throwable {
        App.logger.info("Getting my private key from keystore...");
        return (PrivateKey) this.ks.getKey(this.myAlias, this.keystorePass);
    }

    /**
     * Get the public key with the contact's alias
     * @return PublicKey
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public PublicKey getContactPublic() throws Throwable {
        App.logger.info("Getting my contact's public key from keystore...");
        return this.ks.getCertificate(this.contactAlias).getPublicKey();
    }
}
