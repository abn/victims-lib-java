package com.redhat.victims;

import static org.junit.Assert.assertTrue;

import java.io.IOException;

import org.junit.Test;

import com.redhat.victims.database.VictimsDB;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.database.sql.VictimsSqlDB;

public class VictimsSqlDatabaseTest extends VictimsDatabaseTest {

    static {
        System.setProperty(VictimsConfig.Key.DB_BACKEND, "sqldb");
    }

    @Test
    public void testSqlDBInstance() {
        assertTrue("Unexpected database class",
                VictimsSqlDB.class.isInstance(vdb));
    }

    @Test(expected = VictimsException.class)
    public void testDerby() throws IOException, VictimsException {
        String oldDriver = System.getProperty(VictimsConfig.Key.DB_DRIVER);
        try {
            System.setProperty(VictimsConfig.Key.DB_DRIVER,
                    "org.apache.derby.jdbc.EmbeddedDriver");
            VictimsDBInterface vdb = VictimsDB.db();
            vdb.synchronize();
        } finally {
            resetProperty(VictimsConfig.Key.DB_DRIVER, oldDriver);
        }

    }
}