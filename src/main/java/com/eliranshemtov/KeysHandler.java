package com.eliranshemtov;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeysHandler {
    private final char[] keystorePass;
    private final String myAlias;
    private final String contactAlias;
    private final KeyStore ks;

    public KeysHandler(String keystoreFilePath, String keystorePass, String myAlias, String contactAlias) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        App.logger.info("Initializing KeysHandler for keystore: '{}' where my key's alias is '{}' and my contact's is '{}'", keystoreFilePath, myAlias, contactAlias);
        this.keystorePass = keystorePass.toCharArray();
        this.myAlias = myAlias;
        this.contactAlias = contactAlias;
        this.ks = KeyStore.getInstance("JKS");
        this.ks.load(new FileInputStream(keystoreFilePath), this.keystorePass);
    }

    public PrivateKey getMyPrivate() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        App.logger.info("Getting my private key from keystore...");
        return (PrivateKey) this.ks.getKey(this.myAlias, this.keystorePass);
    }

    public PublicKey getContactPublic() throws KeyStoreException {
        App.logger.info("Getting my contact's public key from keystore...");
        return this.ks.getCertificate(this.contactAlias).getPublicKey();
    }
}
