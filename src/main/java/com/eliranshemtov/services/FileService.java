package com.eliranshemtov.services;

import com.eliranshemtov.App;

import java.io.*;
import java.util.Arrays;
import java.util.Properties;

import static com.eliranshemtov.control.Constants.*;

public class FileService {
    public static void updatePropsFile(byte[] digitalSignature, byte[] encryptedSecretKey, byte[] iv,
                                       String symmetricEncryptionAlgorithm,
                                       String asymmetricTransformationForKeyEncryption,
                                       String symmetricCipherTransformation,
                                       String signatureAlgorithm) throws IOException {
        App.logger.info("Saving properties into '{}' file...", META_PATH);
        Properties props = new Properties();
        props.setProperty(DIGITAL_SIGNATURE, Arrays.toString(digitalSignature));
        props.setProperty(ENCRYPTED_ENCRYPTION_KEY, Arrays.toString(encryptedSecretKey));
        props.setProperty(IV, Arrays.toString(iv));
        props.setProperty(SYMMETRIC_ENCRYPTION_ALG, symmetricEncryptionAlgorithm);
        props.setProperty(ASYMMETRIC_TRANSFORMATION_FOR_KEY_ENCRYPTION, asymmetricTransformationForKeyEncryption);
        props.setProperty(SYMMETRIC_CIPHER_TRANSFORMATION, symmetricCipherTransformation);
        props.setProperty(SIGNATURE_ALG, signatureAlgorithm);

        try (FileWriter fileWriter = new FileWriter(META_PATH)){
            props.store(fileWriter, "Encryption details");
        }
    }

    public static Properties loadDecryptionProps() throws Throwable {
        App.logger.info("Loading decryption properties from config file '{}'", META_PATH);
        File configFile = new File(META_PATH);
        Properties props = new Properties();
        try (FileReader fileReader = new FileReader(configFile)) {
            props.load(fileReader);
        }
        return props;
    }

    public static byte[] parsePropAsBytesArray(String prop){
        String[] byteValues = prop.substring(1, prop.length() - 1).split(",");
        byte[] bytes = new byte[byteValues.length];
        for (int i=0, len=bytes.length; i<len; i++) {
            bytes[i] = Byte.parseByte(byteValues[i].trim());
        }
        return bytes;
    }
}
