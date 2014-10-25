package com.redhat.victims.database.model;

import javax.persistence.*;

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

    @ManyToOne
    @JoinColumn(foreignKey = @ForeignKey(name = "FK_RECORD"))
    private Record record;

    @Column(name = "property")
    private String property;

    @Column(name = "value")
    private String value;

    public Metadata() {

    }

    public Metadata(Record record, String property, String value) {
        this.record = record;
        this.property = property;
        this.value = value;
    }

    public String getProperty() {
        return property;
    }

    public void setProperty(String property) {
        this.property = property;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Record getRecord() {
        return record;
    }

    public void setRecord(Record record) {
        this.record = record;
    }
}
