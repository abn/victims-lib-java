package com.redhat.victims.database;

import com.redhat.victims.database.model.Cache;
import org.hibernate.Session;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

/**
 * Created by abn on 10/26/14.
 */
public class VictimsResultCache {

    public static HashSet<String> get(String hash) {
        Session session = VictimsHibernate.openSession();
        try {
            Cache cache = (Cache) session.get(Cache.class, hash);
            if (cache == null) {
                return null;
            }
            return new HashSet<String>(cache.getCveList());
        } finally {
            session.close();
        }
    }

    public static void put(String hash, HashSet<String> cveSet) {
        Session session = VictimsHibernate.openSession();
        try {
            List<String> cveList = new ArrayList<String>();
            cveList.addAll(cveSet);
            session.save(new Cache(hash, cveList));
        } finally {
            session.close();
        }
    }

    public static void purge() {
        Session session = VictimsHibernate.openSession();
        try {
            session.createSQLQuery("DELETE FROM Cache").executeUpdate();
        } finally {
            session.close();
        }
    }

}
