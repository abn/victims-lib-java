package com.redhat.victims.database;

import com.redhat.victims.VictimsConfig;
import com.redhat.victims.VictimsException;
import com.redhat.victims.VictimsRecord;
import com.redhat.victims.VictimsService;
import com.redhat.victims.database.model.CVE;
import com.redhat.victims.database.model.FileHash;
import com.redhat.victims.database.model.Metadata;
import com.redhat.victims.database.model.Record;
import com.redhat.victims.database.model.Status;
import com.redhat.victims.fingerprint.Algorithms;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.hibernate.Criteria;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.Transaction;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;

/**
 * Created by abn on 10/26/14.
 */
public class VictimsDatabase implements VictimsDBInterface {

    @Override
    public Date lastUpdated() throws VictimsException {
        Throwable throwable = null;
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(
                    VictimsRecord.DATE_FORMAT);
            Date since;

            // The default start
            since = sdf.parse("1970-01-01T00:00:00");

            if (VictimsConfig.forcedUpdate()) {
                return since;
            }

            Session session = VictimsHibernate.openSession();
            Status lastUpdated = (Status) session.get(Status.class, StatusKey.LAST_UPDATED.toString());
            if (lastUpdated == null) {
                since = sdf.parse(lastUpdated.getValue());
            }
            return since;
        } catch (ParseException e) {
            throwable = e;
        }
        throw new VictimsException("Failed to retreive last updated data",
                throwable);
    }

    private void setLastUpdate(Date date) {
        Session session = VictimsHibernate.openSession();
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(VictimsRecord.DATE_FORMAT);
            session.save(new Status(StatusKey.LAST_UPDATED.toString(), sdf.format(date)));
        } finally {
            session.close();
        }
    }

    protected void removeHashes(HashSet<String> hashes) {
        Session session = VictimsHibernate.openSession();
        String hql = "DELETE FROM Record r WHERE r.hash in :hashes";
        try {
            session.createQuery(hql).setParameterList("hashes", hashes).executeUpdate();
        } finally {
            session.close();
        }
    }

    protected int remove(VictimsService.RecordStream recordStream) throws IOException {
        HashSet<String> hashes = new HashSet<String>();
        while (recordStream.hasNext()) {
            hashes.add(recordStream.getNext().hash);
        }
        removeHashes(hashes);
        return hashes.size();
    }

    protected int update(VictimsService.RecordStream recordStream) throws IOException {
        int count = 0;
        Session session = VictimsHibernate.openSession();
        try {
            Record record;
            while (recordStream.hasNext()) {
                VictimsRecord vr = recordStream.getNext();
                String hash = vr.hash.trim();
                Set<String> filehashes = vr.getHashes(Algorithms.SHA512).keySet();

                record = new Record(hash, filehashes.size());
                session.delete(record);
                session.save(record);

                Transaction transaction = session.beginTransaction();
                Integer tcount = 0;

                // insert filehashes
                for (String filehash : filehashes) {
                    VictimsHibernate.saveBatch(session, tcount++, new FileHash(record, filehash));
                }
                // insert metadata key-value pairs
                HashMap<String, String> md = vr.getFlattenedMetaData();
                for (String key : md.keySet()) {
                    VictimsHibernate.saveBatch(session, tcount++, new Metadata(record, key.trim(), md.get(key).trim()));
                }

                // insert cves
                for (String cve : vr.cves) {
                    VictimsHibernate.saveBatch(session, tcount++, new CVE(record, cve.trim()));
                }

                transaction.commit();

                count++;
            }
        } finally {
            session.close();
        }
        return count;
    }

    @Override
    public void synchronize() throws VictimsException {

        Throwable throwable = null;
        try {
            VictimsService service = new VictimsService();
            Date since = lastUpdated();

            int removed = remove(service.removed(since));
            int updated = update(service.updates(since));

            if (removed > 0 || updated > 0) {
                VictimsResultCache.purge();
            }

            setLastUpdate(new Date());
        } catch (IOException e) {
            throwable = e;
        }

        if (throwable != null) {
            throw new VictimsException("Failed to sync database", throwable);
        }
    }

    /**
     * Internal method implementing search for vulnerabilities checking if the
     * given {@link VictimsRecord}'s contents are a superset of a record in the
     * victims database.
     *
     * @param vr
     * @return
     */
    protected HashSet<String> getEmbeddedVulnerabilities(VictimsRecord vr) {
        HashSet<String> cves = new HashSet<String>();

        Set<String> fileHashes = vr.getHashes(Algorithms.SHA512).keySet();
        if (fileHashes.size() <= 0) {
            return cves;
        }

        Session session = VictimsHibernate.openSession();
        try {
            Criteria matchCriteria = session.createCriteria(FileHash.class)
                    .add(Restrictions.in("filehash", fileHashes))
                    .setProjection(Projections.projectionList()
                            .add(Projections.groupProperty("record"))
                            .add(Projections.count("filehash")));
            for (Object object : matchCriteria.list()) {
                Object[] tuple = (Object[]) object;
                Record record = (Record) tuple[0];
                Long count = (Long) tuple[1];
                if (count.equals(new Long(record.getFileCount()))) {
                    for (CVE c : record.getCves()) {
                        cves.add(c.getCve());
                    }
                }
            }
        } finally {
            session.close();
        }
        return cves;
    }

    public HashSet<String> getVulnerabilities(VictimsRecord vr)
            throws VictimsException {
        try {

            HashSet<String> cached = VictimsResultCache.get(vr.hash);
            if (cached != null) {
                return cached;
            }

            HashSet<String> cves = new HashSet<String>();

            // Match jar sha512
            cves.addAll(getVulnerabilities(vr.hash.trim()));

            // Match any embedded filehashes
            cves.addAll(getEmbeddedVulnerabilities(vr));

            VictimsResultCache.put(vr.hash, cves);
            return cves;
        } catch (Throwable e) {
            throw new VictimsException(
                    "Could not determine vulnerabilities for hash: " + vr.hash,
                    e);
        }
    }

    @Override
    public HashSet<String> getVulnerabilities(String sha512) throws VictimsException {
        Session session = VictimsHibernate.openSession();
        try {
            HashSet<String> cves = new HashSet<String>();
            for (Record record : (List<Record>) session.createCriteria(Record.class)
                    .add(Restrictions.eq("hash", sha512)).list()) {
                cves.addAll(record.getCveNames());
            }
            return cves;
        } finally {
            session.close();
        }
    }

    @Override
    public HashSet<String> getVulnerabilities(HashMap<String, String> props) throws VictimsException {
        Session session = VictimsHibernate.openSession();
        try {
            HashSet<String> cves = new HashSet<String>();

            List<Metadata.MetadataProperty> properties = new ArrayList<Metadata.MetadataProperty>();
            for (String key : props.keySet()) {
                properties.add(new Metadata.MetadataProperty(key, props.get(key)));
            }

            String hql = "SELECT m.record, count(*) FROM Metadata m WHERE m.property IN :propset GROUP BY m.record";
            Query propMatch = session.createQuery(hql);
            propMatch.setParameterList("propset", properties);

            for (Object obj : propMatch.list()) {
                Object[] tuple = (Object[]) obj;
                Record record = (Record) tuple[0];
                Long count = (Long) tuple[1];
                if (count.equals(new Long(props.size()))) {
                    for (CVE c : record.getCves()) {
                        cves.add(c.getCve());
                    }
                }
            }
            return cves;
        } finally {
            session.close();
        }
    }

    @Override
    public int getRecordCount() throws VictimsException {
        Session session = VictimsHibernate.openSession();
        try {
            return (Integer) session.createCriteria(Record.class).setProjection(Projections.rowCount()).list().get(0);
        } finally {
            session.close();
        }
    }

}
