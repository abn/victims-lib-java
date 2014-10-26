package com.redhat.victims.database;

import java.util.Set;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import org.reflections.Reflections;

/**
 * Created by abn on 10/25/14.
 */
public class VictimsHibernate {


    protected static Set<Class<?>> getMappedClasses() {
        Reflections reflections = new Reflections(VictimsHibernate.class.getPackage().getName() + ".model");
        return reflections.getTypesAnnotatedWith(javax.persistence.Entity.class);
    }

    public static SessionFactory makeSessionFactory() {
        ServiceRegistry serviceRegistry;
        Configuration configuration = new Configuration();
        configuration.configure();
        configuration.setProperties(VictimsDatabaseConfig.getProperties());

        for (Class<?> clazz : getMappedClasses()) {
            configuration.addAnnotatedClass(clazz);
        }

        serviceRegistry = new StandardServiceRegistryBuilder().applySettings(
                configuration.getProperties()).build();
        return configuration.buildSessionFactory(serviceRegistry);
    }

    public static void saveBatch(Session session, Integer count, Object object) {
        session.save(object);
        if (count % VictimsDatabaseConfig.getBatchSize() == 0) {
            session.flush();
            session.clear();
        }
    }

    public static void deleteBatch(Session session, Integer count, Object object) {
        session.delete(object);
        if (count % VictimsDatabaseConfig.getBatchSize() == 0) {
            session.flush();
            session.clear();
        }
    }
}
