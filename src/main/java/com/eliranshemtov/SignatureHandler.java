package com.eliranshemtov;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.io.*;
import java.security.*;
import static com.eliranshemtov.Constants.BUFFER_SIZE;


public class SignatureHandler {
    private final KeysHandler keysHandler;
    private final Signature signature;

    public SignatureHandler(KeysHandler keysHandler, String signatureAlgorithm) throws NoSuchAlgorithmException {
        App.logger.info("Initializing SignatureHandler...");
        this.keysHandler = keysHandler;
        this.signature = Signature.getInstance(signatureAlgorithm);
    }

    public byte[] sign(String filePath) throws NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, InvalidKeyException, SignatureException {
        App.logger.info("Generating a digital signature of the file content from path: '{}'", filePath);
        this.signature.initSign(this.keysHandler.getMyPrivate());
        try (FileInputStream fis = new FileInputStream(filePath); BufferedInputStream bufferedInputStream = new BufferedInputStream(fis)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = bufferedInputStream.read(buffer)) >= 0) {
                this.signature.update(buffer, 0, bytesRead);
            }
        }
        App.logger.info("Returning a digital signature of the file's content");
        return this.signature.sign();
    }

    public Boolean verifySignature(String filePath, byte[] digitalSignature, Cipher cipher) throws KeyStoreException, InvalidKeyException, IOException, SignatureException {
        App.logger.info("Verifying digital signature to verify completeness");
        PublicKey contactPublicKey = this.keysHandler.getContactPublic();
        this.signature.initVerify(contactPublicKey);
        try (InputStream is = new FileInputStream(filePath)) {
            try (CipherInputStream cis = new CipherInputStream(is, cipher)) {
                byte[] input = new byte[cipher.getBlockSize()];
                int bytesRead;
                while ((bytesRead = cis.read(input)) >= 0) {
                    this.signature.update(input, 0, bytesRead);
                }
            }
            return this.signature.verify(digitalSignature);
        }
    }
}
