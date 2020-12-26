package com.eliranshemtov;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeysHandler {
    private final char[] keystorePass;
    private final KeyStore ks;

    public KeysHandler(String keystoreFilePath, String keystorePass) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        this.keystorePass = keystorePass.toCharArray();
        this.ks = KeyStore.getInstance("JKS");
        this.ks.load(new FileInputStream(keystoreFilePath), this.keystorePass);
    }

    public PrivateKey getMyPrivate() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) this.ks.getKey("my", this.keystorePass);
    }

    public PublicKey getMyPublic() throws KeyStoreException {
        return this.ks.getCertificate("my").getPublicKey();
    }

    public PrivateKey getContactPrivate() throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return (PrivateKey) this.ks.getKey("contact", this.keystorePass);
    }

    public PublicKey getContactPublic() throws KeyStoreException {
        return this.ks.getCertificate("contact").getPublicKey();
    }


}
