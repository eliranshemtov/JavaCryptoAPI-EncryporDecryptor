package com.eliranshemtov;

public final class Constants {

    private Constants() {
        // restrict instantiation
    }

    public static final int BUFFER_SIZE = 1024;
    public static final String IV = "IV";
    public static final String ENCRYPTED_ENCRYPTION_KEY = "EncryptedEncryptionKey";
    public static final String DIGITAL_SIGNATURE = "DigitalSignature";
    public static final String SIGNATURE_ALG = "SignatureAlgorithm";
    public static final String DECRYPTED_OUTPUT_PATH = "decrypted.txt";
    public static final String SYMMETRIC_ENCRYPTION_ALG = "SymmetricEncryptionAlgorithm";
    public static final String SYMMETRIC_CIPHER_TRANSFORMATION = "SymmetricTransformation";
    public static final String ASYMMETRIC_TRANSFORMATION_FOR_KEY_ENCRYPTION = "AsymmetricTransformationForKeyEncryption";
    public static final String INVALID_SIG_ERR_MSG = "Digital Signature is invalid!";
    public static final String META_PATH = "meta.properties";

}