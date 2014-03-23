package com.redhat.victims;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashSet;

import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.redhat.victims.VictimsService.RecordStream;
import com.redhat.victims.database.VictimsDB;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.fingerprint.Algorithms;
import com.redhat.victims.mock.MockEnvironment;

public class VictimsDatabaseTest {

    protected static VictimsDBInterface vdb = null;

    @BeforeClass
    public static void setUp() throws IOException, VictimsException {
        File updateResponse = new File(Resources.TEST_RESPONSE);
        MockEnvironment.setUp(updateResponse, null);
    }

    @AfterClass
    public static void tearDown() {
        MockEnvironment.tearDown();
    }

    public static void sync() throws VictimsException {
        vdb = VictimsDB.db();
        vdb.synchronize();
    }

    @Before
    public void initiate() throws VictimsException {
        // we do this here and not in setUp to allow for different backends
        // to share same test cases
        if (vdb == null) {
            sync();
        }
    }

    protected static void resetProperty(String key, String old) {
        if (old != null) {
            System.setProperty(key, old);
        } else {
            System.clearProperty(key);
        }
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

    private void testVulnerabilities(VictimsDBInterface vdb)
            throws IOException, VictimsException {
        FileInputStream fin = new FileInputStream(Resources.TEST_RESPONSE);
        RecordStream rs = new RecordStream(fin);
        VictimsRecord vr;
        while (rs.hasNext()) {
            vr = rs.getNext();
            if (vr.getHashes(Algorithms.SHA512).size() > 0) {
                HashSet<String> cves = getVulnerabilities(vdb, vr);
                vr.hash = "0";
                HashSet<String> result = getVulnerabilities(vdb, vr);
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
        testVulnerabilities(vdb);
    }

    @Test
    public void testResync() throws VictimsException {
        VictimsDBInterface vdb = VictimsDB.db();
        vdb.synchronize();
    }
}
