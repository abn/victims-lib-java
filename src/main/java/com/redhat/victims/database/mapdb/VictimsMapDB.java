package com.redhat.victims.database.mapdb;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.NavigableSet;

import org.apache.commons.io.FilenameUtils;
import org.mapdb.Atomic;
import org.mapdb.BTreeKeySerializer;
import org.mapdb.DB;
import org.mapdb.DBMaker;
import org.mapdb.Fun;
import org.mapdb.Fun.Tuple2;
import org.mapdb.HTreeMap;

import com.redhat.victims.VictimsConfig;
import com.redhat.victims.VictimsException;
import com.redhat.victims.VictimsRecord;
import com.redhat.victims.VictimsResultCache;
import com.redhat.victims.VictimsService;
import com.redhat.victims.VictimsService.RecordStream;
import com.redhat.victims.database.VictimsDBInterface;
import com.redhat.victims.fingerprint.Algorithms;

public class VictimsMapDB implements VictimsDBInterface {

    protected String DB_NAME = "victims.mapdb";
    protected String DB_PATH = DB_NAME;

    protected DB db;

    protected Atomic.Long keyinc;
    protected Atomic.Long updatedTimeStamp;

    protected HTreeMap<String, Long> checksums;
    protected NavigableSet<Fun.Tuple2<Long, String>> cves;
    protected NavigableSet<Fun.Tuple2<String, Long>> fingerprints;
    protected HTreeMap<Long, Long> fingerprintcount;

    protected VictimsResultCache cache;

    public VictimsMapDB() throws VictimsException {
        DB_PATH = FilenameUtils.concat(VictimsConfig.home().getAbsolutePath(),
                DB_PATH);

        db = DBMaker.newFileDB(new File(DB_PATH)).closeOnJvmShutdown().make();

        keyinc = db.getAtomicLong("record_keyinc");
        updatedTimeStamp = db.getAtomicLong("update_timestamp");

        fingerprintcount = db.createHashMap("fingerprintcount").makeOrGet();

        cves = db.createTreeSet("cves").serializer(BTreeKeySerializer.TUPLE2)
                .makeOrGet();

        checksums = db.createHashMap("checksums").makeOrGet();

        fingerprints = db.createTreeSet("fingerprints")
                .serializer(BTreeKeySerializer.TUPLE2).makeOrGet();
        cache = new VictimsResultCache();
    }

    @Override
    public Date lastUpdated() throws VictimsException {
        if (VictimsConfig.forcedUpdate()) {
            return new Date(0L);
        } else {
            return new Date(updatedTimeStamp.get());
        }
    }

    private int remove(RecordStream rs) throws IOException {
        int count = 0;
        VictimsRecord vr = null;
        while (rs.hasNext()) {
            vr = rs.getNext();

            if (checksums.containsKey(vr.hash)) {
                Long id = checksums.get(vr.hash);

                Iterator<Tuple2<String, Long>> it = fingerprints.iterator();
                while (it.hasNext()) {
                    Fun.Tuple2<String, Long> item = it.next();
                    if (item.b.equals(id)) {
                        fingerprints.remove(item);
                    }
                }

                for (String cve : Fun.filter(cves, id)) {
                    cves.remove(Fun.t2(id, cve));
                }

                count++;
            }
        }

        return count;
    }

    private int update(RecordStream rs) throws IOException {
        int count = 0;

        VictimsRecord vr = null;
        while (rs.hasNext()) {
            long id = keyinc.getAndIncrement();
            vr = rs.getNext();

            checksums.put(vr.hash, id);

            for (String cve : vr.cves) {
                cves.add(Fun.t2(id, cve));
            }

            for (String fingerprint : vr.getHashes(Algorithms.SHA512).keySet()) {
                fingerprints.add(Fun.t2(fingerprint, id));
            }

            fingerprintcount.put(id, (long) vr.getHashes(Algorithms.SHA512)
                    .size());

            count++;
        }

        return count;
    }

    @Override
    public void synchronize() throws VictimsException {
        try {
            VictimsService service = new VictimsService();
            Date since = lastUpdated();

            int removed = remove(service.removed(since));
            int updated = update(service.updates(since));

            if (removed > 0 || updated > 0) {
                cache.purge();
            }
            updatedTimeStamp.set((new Date()).getTime());
            db.commit();
        } catch (IOException e) {
            throw new VictimsException("Failed to sych database");
        }
    }

    @Override
    public HashSet<String> getVulnerabilities(VictimsRecord vr)
            throws VictimsException {
        HashSet<String> cveMatches = new HashSet<String>();

        AutoCounter result = new AutoCounter();
        // find all records for which we have hashes for
        for (String fingerprint : vr.getHashes(Algorithms.SHA512).keySet()) {
            for (Long l : Fun.filter(fingerprints, fingerprint)) {
                result.put(l);
            }
        }

        for (Long l : result.keySet()) {
            Long count = result.getValue(l);
            if (fingerprintcount.get(l) == count) {
                for (String cve : Fun.filter(cves, l)) {
                    cveMatches.add(cve);
                }
            }
        }

        return cveMatches;
    }

    @Override
    public HashSet<String> getVulnerabilities(String sha512)
            throws VictimsException {
        Long id = checksums.get(sha512);
        HashSet<String> cveMatches = new HashSet<String>();
        for (String cve : Fun.filter(cves, id)) {
            cveMatches.add(cve);
        }
        return cveMatches;
    }

    @Override
    public HashSet<String> getVulnerabilities(HashMap<String, String> props)
            throws VictimsException {
        // TODO: Implement
        return new HashSet<String>();
    }

    @Override
    public int getRecordCount() throws VictimsException {
        return checksums.size();
    }

    protected static class MutableLong {
        /*
         * http://stackoverflow.com/questions/81346
         */
        Long value = 1L; // note that we start at 1 since we're counting

        public void increment() {
            ++value;
        }

        public Long get() {
            return value;
        }
    }

    @SuppressWarnings("serial")
    public static class AutoCounter extends HashMap<Long, MutableLong> {

        public Long getValue(Object key) {
            return (long) super.get(key).get();
        }

        public void put(Long key) {
            if (super.containsKey(key)) {
                super.get(key).increment();
            } else {
                super.put(key, new MutableLong());
            }
        }
    }

}
