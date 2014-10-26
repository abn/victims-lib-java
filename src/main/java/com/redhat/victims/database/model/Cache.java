package com.redhat.victims.database.model;

import java.util.List;
import javax.persistence.CollectionTable;
import javax.persistence.ElementCollection;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

/**
 * Created by abn on 10/26/14.
 */
@Entity
@Table
public class Cache {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String hash;

    @ElementCollection
    @CollectionTable
    private List<String> cveList;

    public Cache() {
    }

    public Cache(String hash, List<String> cveList) {
        this.hash = hash;
        this.cveList = cveList;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public List<String> getCveList() {
        return cveList;
    }

    public void setCveList(List<String> cveList) {
        this.cveList = cveList;
    }
}
