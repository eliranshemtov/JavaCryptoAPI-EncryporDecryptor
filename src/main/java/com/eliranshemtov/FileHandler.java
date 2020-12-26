package com.eliranshemtov;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;

public class FileHandler {
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
}
