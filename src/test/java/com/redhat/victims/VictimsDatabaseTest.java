package com.redhat.victims;

import com.redhat.victims.VictimsService.RecordStream;
import com.redhat.victims.database.VictimsDB;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.fingerprint.Algorithms;
import com.redhat.victims.mock.MockEnvironment;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import org.apache.commons.io.FileUtils;
import org.hibernate.boot.registry.classloading.spi.ClassLoadingException;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class VictimsDatabaseTest {

    private static VictimsDBInterface vdb;

    @BeforeClass
    public static void setUp() throws IOException, VictimsException {
        File updateResponse = new File(Resources.TEST_RESPONSE);
        MockEnvironment.setUp(updateResponse, null);
        sync();
    }

    @AfterClass
    public static void tearDown() {
        MockEnvironment.tearDown();
    }

    public static void sync() throws VictimsException {
        vdb = VictimsDB.db();
        vdb.synchronize();
    }

    @Test
    public void testSynchronize() throws VictimsException, IOException {
        String sha512 = FileUtils.readFileToString(
                new File(Resources.TEST_SHA512)).trim();
        String cve = FileUtils.readFileToString(new File(Resources.TEST_CVE))
                .trim();
        assertTrue("Synchronized DB does not contain expected hash.", vdb
                .getVulnerabilities(sha512).contains(cve));
    }

    private HashSet<String> getVulnerabilities(VictimsDBInterface vdb,
            VictimsRecord vr) throws VictimsException {
        return vdb.getVulnerabilities(vr);
    }

    private void testVulnerabilities(VictimsDBInterface vdb, boolean embedded, boolean meta)
            throws IOException, VictimsException {
        FileInputStream fin = new FileInputStream(Resources.TEST_RESPONSE);
        RecordStream rs = new RecordStream(fin);
        VictimsRecord vr;
        while (rs.hasNext()) {
            vr = rs.getNext();
            if (vr.getHashes(Algorithms.SHA512).size() > 0) {
                HashSet<String> cves = getVulnerabilities(vdb, vr);
                HashSet<String> result;

                if (meta) {
                    HashMap<String, String> metadata = vr.getFlattenedMetaData();
                    result = vdb.getVulnerabilities(metadata);
                    for (String key : metadata.keySet()) {
                        metadata.put(key, "THISREALLYSHOULDNOTEXIST");
                    }
                    assertEquals("Negative case for property match failed.", 0, vdb.getVulnerabilities(metadata).size());
                } else {
                    vr.hash = "0";
                    if (embedded) {
                        // since we are testing for embedded, inject some new
                        // filehashes to simulate a superset
                        vr.getHashes(Algorithms.SHA512).put("1", "1");
                        vr.getHashes(Algorithms.SHA512).put("2", "2");
                    }
                    result = getVulnerabilities(vdb, vr);
                }
                assertEquals("Unexpected number of CVEs", cves.size(),
                        result.size());
                for (String cve : cves) {
                    assertTrue(String.format(
                            "%s was expected, but was not found in result.",
                            cve), result.contains(cve));
                }
                break;
            }
        }
    }

    @Test
    public void testVulnerabilities() throws IOException, VictimsException {
        testVulnerabilities(vdb, false, false);
    }

    @Test
    public void testEmbeddedVulnerabilities() throws IOException,
            VictimsException {
        testVulnerabilities(vdb, true, false);
    }

    @Test
    public void testPropertyVulnerabilities() throws IOException, VictimsException {
        testVulnerabilities(vdb, false, true);
    }

    @Test
    public void testResync() throws VictimsException {
        VictimsDBInterface vdb = VictimsDB.db();
        vdb.synchronize();
    }

    @Test(expected = ClassLoadingException.class)
    public void testDerby() throws IOException, VictimsException {
        String old = System.getProperty(VictimsConfig.Key.DB_DRIVER);
        try {
            System.setProperty(VictimsConfig.Key.DB_DRIVER,
                    "org.apache.derby.jdbc.EmbeddedDriver");
            VictimsDBInterface vdb = VictimsDB.db();
            vdb.synchronize();
        } finally {
            if (old != null) {
                System.setProperty(VictimsConfig.Key.DB_DRIVER, old);
            } else {
                System.clearProperty(VictimsConfig.Key.DB_DRIVER);
            }
        }

    }
}
