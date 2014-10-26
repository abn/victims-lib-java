package com.redhat.victims.database;

import com.redhat.victims.VictimsConfig;
import com.redhat.victims.database.model.Cache;
import java.util.HashSet;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

/**
 * Created by abn on 10/26/14.
 */
public class VictimsResultCache {

    private SessionFactory sessionFactory;

    public VictimsResultCache(SessionFactory sessionFactory) {
        init(sessionFactory);
    }

    public VictimsResultCache() {
        init(VictimsHibernate.makeSessionFactory());
    }

    private void init(SessionFactory sessionFactory) {
        this.sessionFactory = sessionFactory;
        if (VictimsConfig.purgeCache()) {
            purge();
        }
    }

    public HashSet<String> get(String hash) {
        Session session = sessionFactory.openSession();
        try {
            Cache cache = (Cache) session.get(Cache.class, hash);
            if (cache == null) {
                return null;
            }
            return cache.getCveSet();
        } finally {
            session.close();
        }
    }

    public void put(String hash, HashSet<String> cveSet) {
        Session session = sessionFactory.openSession();
        try {
            Transaction transaction = session.beginTransaction();
            session.saveOrUpdate(new Cache(hash, cveSet));
            transaction.commit();
        } finally {
            session.close();
        }
    }

    public void purge() {
        Session session = sessionFactory.openSession();
        try {
            Transaction transaction = session.beginTransaction();
            session.createQuery("DELETE FROM Cache").executeUpdate();
            transaction.commit();
        } finally {
            session.close();
        }
    }

    public boolean exists(String hash) {
        return get(hash) != null;
    }

}
