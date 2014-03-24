package com.redhat.victims;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;

import org.junit.Test;

import com.redhat.victims.database.VictimsMapDB;
import com.redhat.victims.fingerprint.Algorithms;

public class VictimsConfigTest extends VictimsTest {

    @Test
    public void testAlgorithms() {
        // test defaults
        ArrayList<Algorithms> results = VictimsConfig.algorithms();

        assertTrue("Unexpected default algorithm configuration.",
                results.contains(VictimsConfig.getDefaultAlgorithm()));

        // test legal set
        System.setProperty(VictimsConfig.Key.ALGORITHMS, "SHA512");
        results = VictimsConfig.algorithms();
        assertTrue("Algorithms were not set correctly.",
                results.contains(Algorithms.SHA512) && results.size() == 1);

        // test legal with illegal set
        System.setProperty(VictimsConfig.Key.ALGORITHMS, "MD1, SHA512");
        results = VictimsConfig.algorithms();
        assertTrue("Algorithms were not set correctly.",
                results.contains(Algorithms.SHA512) && results.size() == 1);

        // test all invalids
        System.setProperty(VictimsConfig.Key.ALGORITHMS, "MD1,DUMMY");
        results = VictimsConfig.algorithms();
        Algorithms expected = VictimsConfig.getDefaultAlgorithm();
        assertTrue("Unexpected algorithm(s) returned for invalid config.",
                results.size() == 1 && results.contains(expected));
    }

    @Test
    public void testBackendConfig() {
        String key = VictimsConfig.Key.DB_BACKEND;
        String old = System.getProperty(key);
        try {
            // test default
            System.clearProperty(key);
            assertEquals("Unexpected default backend config.",
                    VictimsConfig.dbBackend(),
                    VictimsConfig.DEFAULT_PROPS.get(key));

            // test invalid
            System.setProperty(key, "foobar");
            try {
                VictimsConfig.dbBackendInstance();
                fail("DB backend instance was successfully created for invalid config.");
            } catch (VictimsException e) {
                // pass
            }

            // test classname
            System.setProperty(key, VictimsMapDB.class.getCanonicalName());
            assertTrue("DB instance not correctly created for valid classname",
                    VictimsMapDB.class.isInstance(VictimsConfig
                            .dbBackendInstance()));

            // test invalid classname
            System.setProperty(key, VictimsConfig.class.getCanonicalName());
            try {
                VictimsConfig.dbBackendInstance();
                fail("DB backend instance was successfully created with invalid class instance.");
            } catch (VictimsException e) {
                // pass
            }
        } catch (VictimsException e) {
            fail("Something went wrong when testing backend config: "
                    + e.getMessage());
        } finally {
            resetProperty(key, old);
        }
    }
}