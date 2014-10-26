package com.redhat.victims.database.model;

import java.util.HashSet;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import org.apache.commons.lang.StringUtils;

/**
 * Created by abn on 10/26/14.
 */
@Entity
@Table
public class Cache {

    @Id
    private String hash;

    @Column
    private String vulnerabilities;

    public Cache() {
    }

    public Cache(String hash, HashSet<String> cveSet) {
        this.hash = hash;
        this.vulnerabilities = StringUtils.join(cveSet, ",");
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public String getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(String vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

    public HashSet<String> getCveSet() {
        HashSet<String> cveSet = new HashSet<String>();
        for (String cve : StringUtils.split(getVulnerabilities(), ",")) {
            cveSet.add(cve);
        }
        return cveSet;
    }
}