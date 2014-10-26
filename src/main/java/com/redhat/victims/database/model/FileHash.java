package com.redhat.victims.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.ForeignKey;
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
public class FileHash {

    @SuppressWarnings("unused")
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer id;

    @ManyToOne
    @JoinColumn(foreignKey = @ForeignKey(name = "FK_RECORD"))
    private Record record;

    @Column(name = "filehash")
    private String filehash;

    public FileHash() {

    }

    public FileHash(Record record, String filehash) {
        this.filehash = filehash;
        this.record = record;
    }

    public String getFilehash() {
        return filehash;
    }

    public void setFilehash(String filehash) {
        this.filehash = filehash;
    }

    public Record getRecord() {
        return record;
    }

    public void setRecord(Record record) {
        this.record = record;
    }
}
