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
import org.hibernate.Criteria;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.criterion.Projections;
import org.hibernate.criterion.Restrictions;
import org.hibernate.service.ServiceRegistry;
import org.reflections.Reflections;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

/**
 * Created by abn on 10/25/14.
 */
public class VictimsHibernate implements VictimsDBInterface {
    private static SessionFactory sessionFactory;
    private static ServiceRegistry serviceRegistry;
    private static Configuration configuration;

    protected static Properties getConfigurationProperties() {
        Properties properties = new Properties();
        properties.setProperty("hibernate.connection.driver_class", VictimsConfig.dbDriver());
        properties.setProperty("hibernate.connection.url", VictimsConfig.dbUrl());
        properties.setProperty("hibernate.connection.username", VictimsConfig.dbUser());
        properties.setProperty("hibernate.connection.password", VictimsConfig.dbPass());
        properties.setProperty("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        properties.setProperty("hibernate.hbm2ddl.auto", "update");
        properties.setProperty("hibernate.jdbc.batch_size", "20");

        properties.setProperty("hibernate.format_sql", "false");
        properties.setProperty("hibernate.show_sql", "false");
        properties.setProperty("hibernate.connection.pool_size", "2");
        properties.setProperty("hibernate.current_session_context_class", "thread");

        return properties;
    }

    protected static Set<Class<?>> getMappedClasses() {
        Reflections reflections = new Reflections(VictimsHibernate.class.getPackage().getName() + ".model");
        return reflections.getTypesAnnotatedWith(javax.persistence.Entity.class);
    }

    static {
        configuration = new Configuration();
        configuration.configure();
        configuration.setProperties(getConfigurationProperties());

        for(Class<?> clazz : getMappedClasses()) {
            configuration.addAnnotatedClass(clazz);
        }

        serviceRegistry = new StandardServiceRegistryBuilder().applySettings(
                configuration.getProperties()).build();
        sessionFactory = configuration.buildSessionFactory(serviceRegistry);
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

            Session session = sessionFactory.openSession();
            Status lastUpdated = (Status) session.get(Status.class, StatusKey.LAST_UPDATED);
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

    protected void removeHashes(HashSet<String> hashes) {
        Session session = sessionFactory.openSession();
        String hql = "DELETE FROM Record r WHERE r.hash in :hashes";
        try {
            session.createQuery(hql).setParameterList("hashes", hashes).executeUpdate();
        } finally {
            session.close();
        }
    }

    protected int remove(VictimsService.RecordStream recordStream) throws IOException {
        HashSet<String> hashes = new HashSet<String>();
        while(recordStream.hasNext()) {
            hashes.add(recordStream.getNext().hash);
        }
        removeHashes(hashes);
        return hashes.size();
    }

    private void saveBatch(Session session, Integer count, Object object) {
        session.save(object);
        if ( count % Integer.parseInt(configuration.getProperty("hibernate.jdbc.batch_size")) == 0 ) {
            session.flush();
            session.clear();
        }
    }

    protected int update(VictimsService.RecordStream recordStream) throws IOException {
        int count = 0;
        Session session = sessionFactory.openSession();
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
                    saveBatch(session, tcount++, new FileHash(record, filehash));
                }
                // insert metadata key-value pairs
                HashMap<String, String> md = vr.getFlattenedMetaData();
                for (String key : md.keySet()) {
                    saveBatch(session, tcount++, new Metadata(record, key.trim(), md.get(key).trim()));
                }

                // insert cves
                for (String cve : vr.cves) {
                    saveBatch(session, tcount++, new CVE(record, cve.trim()));
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
                //TODO: cache.purge();
            }

            //TODO: setLastUpdate(new Date());
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

        Session session = sessionFactory.openSession();
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
                    for(CVE c : record.getCves()) {
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
            //TODO: cache
            /*if (cache.exists(vr.hash)) {
                return cache.get(vr.hash);
            }*/
            HashSet<String> cves = new HashSet<String>();

            // Match jar sha512
            cves.addAll(getVulnerabilities(vr.hash.trim()));

            // Match any embedded filehashes
            cves.addAll(getEmbeddedVulnerabilities(vr));

            //TODO: cache.add(vr.hash, cves);
            return cves;
        } catch (Throwable e) {
            throw new VictimsException(
                    "Could not determine vulnerabilities for hash: " + vr.hash,
                    e);
        }
    }

    @Override
    public HashSet<String> getVulnerabilities(String sha512) throws VictimsException {
        Session session = sessionFactory.openSession();
        try {
            HashSet<String> cves = new HashSet<String>();
            for (Object obj : session.createCriteria(CVE.class)
                    .createAlias("record", "r")
                    .add(Restrictions.eq("r.hash", sha512)).list()) {
                cves.add(((CVE) obj).getCve());
            }
            return cves;
        } finally {
            session.close();
        }
    }

    @Override
    public HashSet<String> getVulnerabilities(HashMap<String, String> props) throws VictimsException {
        return null;
    }

    @Override
    public int getRecordCount() throws VictimsException {
        Session session = sessionFactory.openSession();
        try {
            return (Integer) session.createCriteria(Record.class).setProjection(Projections.rowCount()).list().get(0);
        } finally {
            session.close();
        }
    }
}
