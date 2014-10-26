package com.redhat.victims;

import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.database.VictimsDatabase;
import com.redhat.victims.database.VictimsResultCache;
import com.redhat.victims.mock.MockEnvironment;
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VictimsResultCacheTest {

    @BeforeClass
    public static void setUp() throws IOException, VictimsException {
        File updateResponse = new File(Resources.TEST_RESPONSE);
        MockEnvironment.setUp(updateResponse, null);
    }

    @AfterClass
    public static void tearDown() {
        MockEnvironment.tearDown();
    }

    private static HashSet<String> cveSet() {
        HashSet<String> cves = new HashSet<String>();
        cves.add("CVE-XXXX-XXXX");
        cves.add("CVE-YYYY-YYYY");
        return cves;
    }

    private VictimsResultCache prepareCache(String hash)
            throws VictimsException {
        VictimsResultCache vrc = new VictimsResultCache();
        vrc.put(hash, cveSet());
        assertTrue("Result was not cached.", vrc.exists(hash));
        return vrc;
    }

    private boolean equal(HashSet<String> r1, HashSet<String> r2) {
        for (String cve : r1) {
            if (!r2.contains(cve)) {
                return false;
            }
        }
        return true;
    }

    @Test
    public void testAdd() throws VictimsException {
        String hash = "0";
        VictimsResultCache vrc = prepareCache(hash);
        HashSet<String> result = vrc.get(hash);
        assertTrue("Cached CVEs vary from returned CVEs.",
                equal(cveSet(), result));
    }

    @Test
    public void testPurge() throws VictimsException {
        String hash = "0";
        VictimsResultCache vrc = prepareCache(hash);
        vrc.purge();
        assertTrue("Cache was not correctly purged.", !vrc.exists(hash));
    }

    @Test
    public void testPurgeConfig() throws VictimsException {
        String hash = "0";
        VictimsResultCache vrc = prepareCache(hash);

        System.setProperty(VictimsConfig.Key.PURGE_CACHE, "true");
        vrc = new VictimsResultCache();
        assertTrue("Cache was not correctly purged via config.",
                !vrc.exists(hash));
        vrc.put(hash, cveSet());

        vrc = new VictimsResultCache();
        assertFalse("Purged state was not maintained between instances.",
                vrc.exists(hash));

        System.clearProperty(VictimsConfig.Key.PURGE_CACHE);

    }

    @Test
    public void testPurgeOnSync() throws VictimsException {
        String hash = "0";
        HashSet<String> test = new HashSet<String>();
        test.add("CVE-FOO-BAR");
        VictimsResultCache vrc = new VictimsResultCache();
        vrc.put(hash, test);
        VictimsDBInterface vdb = new VictimsDatabase();
        vdb.synchronize();
        assertTrue("Cache was not correctly purged on database sync.",
                !vrc.exists(hash));
    }
}
