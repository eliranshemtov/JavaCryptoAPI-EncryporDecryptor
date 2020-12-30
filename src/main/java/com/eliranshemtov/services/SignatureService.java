package com.eliranshemtov.services;

import com.eliranshemtov.App;
import java.io.*;
import java.security.*;
import static com.eliranshemtov.control.Constants.BUFFER_SIZE;


public class SignatureService {
    private final KeysService keysService;
    private final Signature signature;

    /**
     * SignatureService - initializes a signature object that implements the given algorithm, supply signing method and getVerifySignatureObject method.
     * @param keysService - initialized KeysService
     * @param signatureAlgorithm - String that identifies the name of the signature algorithm to be used
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public SignatureService(KeysService keysService, String signatureAlgorithm) throws Throwable {
        App.logger.info("Initializing SignatureHandler...");
        this.keysService = keysService;
        this.signature = Signature.getInstance(signatureAlgorithm);
    }

    /**
     * read a file as plaintext, update the signature object with every chunk of the file's content and generate a signature at the end of the file.
     * @param filePath plaintext file path
     * @return byte array of a a digital signature of the given file's content
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public byte[] sign(String filePath) throws Throwable {
        App.logger.info("Generating a digital signature of the file content from path: '{}'", filePath);
        this.signature.initSign(this.keysService.getMyPrivate());
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

    /**
     * Gets the public key of the contact, and return a signature object, initialized with it, ready for verify digital signature.
     * all that's left is to update the returned object with cleartext content, and call verify() with the original digital signature to verify match between them.
     * @return Signature object, ready for verification, initialized with the public key of the contact.
     * @throws Throwable In order to reduce error handling code overhead, I decided to generalize this, as this is not the main focus of the exercise.
     */
    public Signature getVerifySignatureObject() throws Throwable {
        App.logger.info("Verifying digital signature to verify completeness");
        PublicKey contactPublicKey = this.keysService.getContactPublic();
        this.signature.initVerify(contactPublicKey);
        return this.signature;
    }
}
