package com.redhat.victims.database.model;

import java.io.Serializable;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Embedded;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

/**
 * Created by abn on 10/25/14.
 */
@Entity
@Table
public class Metadata {

    @SuppressWarnings("unused")
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn
    private Record record;

    @Embedded
    private MetadataProperty property;

    public Metadata() {

    }

    public Metadata(Record record, String key, String value) {
        this.record = record;
        this.property = new MetadataProperty(key, value);
    }

    public Record getRecord() {
        return record;
    }

    public void setRecord(Record record) {
        this.record = record;
    }

    public MetadataProperty getProperty() {
        return property;
    }

    public void setProperty(MetadataProperty property) {
        this.property = property;
    }

    @Embeddable
    public static class MetadataProperty implements Serializable {

        @Column
        private String key;

        @Column
        private String value;

        public MetadataProperty() {
        }

        public MetadataProperty(String value, String key) {
            this.value = value;
            this.key = key;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }
    }
}