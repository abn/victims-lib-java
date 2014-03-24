package com.redhat.victims;

public abstract class VictimsTest {

    /**
     * Helper method to rest a config property correctly
     * 
     * @param key
     * @param old
     */
    protected static void resetProperty(String key, String old) {
        if (old != null) {
            System.setProperty(key, old);
        } else {
            System.clearProperty(key);
        }
    }
}
