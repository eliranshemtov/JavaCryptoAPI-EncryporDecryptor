package com.eliranshemtov;

import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// @TODO - verify logs order
// @TODO - Documentation + readme.md
// @TODO - Allow easy providers switch


public class App{
    public static final Logger logger = LoggerFactory.getLogger(App.class);
    public static void main( String[] args ) {
        try {
            CommandLine cmd = new ArgsParser().parse(args);
            Controller controller = new Controller(cmd);
            Cryptor cryptor = controller.getCryptor();
            cryptor.action();
        } catch (Throwable e){
            logger.error("An error occurred: '{}'", e.getMessage());
        }

    }
}

