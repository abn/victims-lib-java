package com.redhat.victims.database;

import com.redhat.victims.VictimsConfig;
import java.io.File;
import java.io.IOException;
import java.util.Properties;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

/**
 * Created by abn on 10/27/14.
 */
public class VictimsDatabaseConfig {

    private static final String HIBERNATE_CONFIGURATION_FILE = FilenameUtils.concat(
            VictimsConfig.getHomeProperty(), "hibernate.properties");
    private static Integer batchSize = 40;

    public static Properties getProperties() {
        Properties properties = new Properties();
        String debug = new Boolean(VictimsConfig.isDatabaseDebug()).toString();

        properties.setProperty("hibernate.connection.driver_class", VictimsConfig.dbDriver());
        properties.setProperty("hibernate.connection.url", VictimsConfig.dbUrl());
        properties.setProperty("hibernate.connection.username", VictimsConfig.dbUser());
        properties.setProperty("hibernate.connection.password", VictimsConfig.dbPass());
        properties.setProperty("hibernate.dialect", VictimsConfig.dbDialect());
        properties.setProperty("hibernate.hbm2ddl.auto", "update");
        properties.setProperty("hibernate.jdbc.batch_size", batchSize.toString());

        properties.setProperty("hibernate.format_sql", debug);
        properties.setProperty("hibernate.show_sql", debug);
        properties.setProperty("hibernate.connection.pool_size", "2");
        properties.setProperty("hibernate.current_session_context_class", "thread");

        // configure overrides
        try {
            File propFile = new File(HIBERNATE_CONFIGURATION_FILE);
            if (propFile.exists()) {
                properties.load(FileUtils.openInputStream(propFile));
                batchSize = new Integer(properties.getProperty("hibernate.jdbc.batch_size"));
            }
        } catch (IOException e) {
            //TODO: Log error
        }
        return properties;
    }

    public static Integer getBatchSize() {
        return batchSize;
    }
}