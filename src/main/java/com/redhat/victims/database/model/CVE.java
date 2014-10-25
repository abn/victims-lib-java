package com.redhat.victims.database.model;

import javax.persistence.*;

/**
 * Created by abn on 10/25/14.
 */
@Entity
@Table
public class CVE {

    @SuppressWarnings("unused")
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    @ManyToOne
    @JoinColumn(foreignKey = @ForeignKey(name = "FK_RECORD"))
    private Record record;

    @Column(name = "cve")
    private String cve;

    public CVE() { }

    public CVE(Record record, String cve) {
        this.record = record;
        this.cve = cve;
    }

    public String getCve() {
        return cve;
    }

    public void setCve(String cve) {
        this.cve = cve;
    }

    public Record getRecord() {
        return record;
    }

    public void setRecord(Record record) {
        this.record = record;
    }
}
