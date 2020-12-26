package com.eliranshemtov;

import java.io.*;
import java.util.Arrays;
import java.util.Properties;
import java.util.Scanner;

public class FileHandler {
    private final static String metaPath = "meta.properties";
    public static String read(String filepath){
        App.logger.info("Reading file: '{}'", filepath);
        StringBuilder fileContent = new StringBuilder();
        try {
            File fileObj = new File(filepath);
            Scanner fileReader = new Scanner(fileObj);
            while (fileReader.hasNextLine()) {
                fileContent.append(fileReader.nextLine());
            }
            fileReader.close();
        } catch (FileNotFoundException e) {
            App.logger.error("An error occurred while trying to read an input file:");
            e.printStackTrace();
        }
        return fileContent.toString();
    }

    public static void write(String data, String filepath){
        App.logger.info("Writing data into file: '{}'", filepath);
        try {
            FileWriter fileWriter = new FileWriter(filepath);
            fileWriter.write(data);
            fileWriter.close();
            App.logger.info("Successfully wrote data to file: {}", filepath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void updatePropsFile(byte[] digitalSignature, byte[] encryptedSecretKey, byte[] iv) throws IOException {
        Properties props = new Properties();
        props.setProperty("digitalSignature", Arrays.toString(digitalSignature));
        props.setProperty("EncryptedEncryptionKey", Arrays.toString(encryptedSecretKey));
        props.setProperty("IV", Arrays.toString(iv));

        try (FileWriter fileWriter = new FileWriter(metaPath)){
            props.store(fileWriter, "Encryption details");
        };
    }

    public static Properties loadDecryptionProps() throws IOException {
        File configFile = new File(metaPath);
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
