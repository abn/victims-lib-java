package com.redhat.victims.database;

import com.redhat.victims.VictimsConfig;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.Configuration;
import org.hibernate.service.ServiceRegistry;
import org.reflections.Reflections;

import java.util.Properties;
import java.util.Set;

/**
 * Created by abn on 10/25/14.
 */
public class VictimsHibernate {
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

        properties.setProperty("hibernate.format_sql", "true");
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

        for (Class<?> clazz : getMappedClasses()) {
            configuration.addAnnotatedClass(clazz);
        }

        serviceRegistry = new StandardServiceRegistryBuilder().applySettings(
                configuration.getProperties()).build();
        sessionFactory = configuration.buildSessionFactory(serviceRegistry);
    }

    public static Session openSession() {
        return sessionFactory.openSession();
    }

    public static void saveBatch(Session session, Integer count, Object object) {
        session.save(object);
        if (count % Integer.parseInt(configuration.getProperty("hibernate.jdbc.batch_size")) == 0) {
            session.flush();
            session.clear();
        }
    }

    public static void deleteBatch(Session session, Integer count, Object object) {
        session.delete(object);
        if (count % Integer.parseInt(configuration.getProperty("hibernate.jdbc.batch_size")) == 0) {
            session.flush();
            session.clear();
        }
    }
}
