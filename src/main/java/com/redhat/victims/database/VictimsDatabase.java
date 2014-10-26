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
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.hibernate.Criteria;
import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;

/**
 * Created by abn on 10/26/14.
 */
public class VictimsDatabase implements VictimsDBInterface {

    private SessionFactory sessionFactory;
    private VictimsResultCache cache;

    public VictimsDatabase() {
        this.sessionFactory = VictimsHibernate.makeSessionFactory();
        this.cache = new VictimsResultCache(this.sessionFactory);
    }

    public Session getSession() {
        return this.sessionFactory.openSession();
    }

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

            Session session = getSession();
            Status lastUpdated = (Status) session.get(Status.class, Status.StatusKey.LAST_UPDATED.toString());
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
        Session session = getSession();
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(VictimsRecord.DATE_FORMAT);
            session.save(new Status(Status.StatusKey.LAST_UPDATED.toString(), sdf.format(date)));
        } finally {
            session.close();
        }
    }

    protected void removeHashes(HashSet<String> hashes) {
        Session session = getSession();
        try {
            Criteria deleteCriteria = session.createCriteria(Record.class).add(Restrictions.in("hash", hashes));
            Transaction txn = session.beginTransaction();
            int deleteCount = 0;
            for (Object record : deleteCriteria.list()) {
                VictimsHibernate.deleteBatch(session, deleteCount++, record);
            }
            txn.commit();
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
        Session session = getSession();
        try {
            Record record;
            while (recordStream.hasNext()) {
                VictimsRecord vr = recordStream.getNext();
                String hash = vr.hash.trim();
                Set<String> fileHashes = vr.getHashes(Algorithms.SHA512).keySet();

                record = new Record(hash, fileHashes.size());
                session.delete(record);
                session.save(record);

                Transaction transaction = session.beginTransaction();
                Integer tCount = 0;

                // insert file hashes
                for (String filehash : fileHashes) {
                    VictimsHibernate.saveBatch(session, tCount++, new FileHash(record, filehash));
                }
                // insert metadata key-value pairs
                HashMap<String, String> md = vr.getFlattenedMetaData();
                for (String key : md.keySet()) {
                    VictimsHibernate.saveBatch(session, tCount++, new Metadata(record, key.trim(), md.get(key).trim()));
                }

                // insert cves
                for (String cve : vr.cves) {
                    VictimsHibernate.saveBatch(session, tCount++, new CVE(record, cve.trim()));
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
                cache.purge();
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

        Session session = getSession();
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
                    for (CVE c : record.getCveList()) {
                        cves.add(c.getName());
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

            HashSet<String> cached = cache.get(vr.hash);
            if (cached != null) {
                return cached;
            }

            HashSet<String> cves = new HashSet<String>();

            // Match jar sha512
            cves.addAll(getVulnerabilities(vr.hash.trim()));

            // Match any embedded filehashes
            cves.addAll(getEmbeddedVulnerabilities(vr));

            cache.put(vr.hash, cves);
            return cves;
        } catch (Throwable e) {
            throw new VictimsException(
                    "Could not determine vulnerabilities for hash: " + vr.hash,
                    e);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public HashSet<String> getVulnerabilities(String sha512) throws VictimsException {
        Session session = getSession();
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
        Session session = getSession();
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
                    for (CVE c : record.getCveList()) {
                        cves.add(c.getName());
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
        Session session = getSession();
        try {
            return (Integer) session.createCriteria(Record.class).setProjection(Projections.rowCount()).list().get(0);
        } finally {
            session.close();
        }
    }
}