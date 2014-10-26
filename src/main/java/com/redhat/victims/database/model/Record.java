package com.redhat.victims.database.model;

import java.util.HashSet;
import java.util.List;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotNull;

/**
 * Created by abn on 10/25/14.
 */
@Entity
@Table(uniqueConstraints = @UniqueConstraint(columnNames = "id"))
public class Record {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column
    private Long id;

    @NotNull
    @Column(length = 128)
    private String hash;

    @NotNull
    @Column
    private Integer fileCount = 0;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "record")
    private List<FileHash> fileHashes;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "record")
    private List<CVE> cveList;

    @OneToMany(cascade = CascadeType.ALL, mappedBy = "record")
    private List<Metadata> metadata;

    public Record() {

    }

    public Record(String hash, Integer fileCount) {
        this.hash = hash;
        this.fileCount = fileCount;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public Integer getFileCount() {
        return fileCount;
    }

    public void setFileCount(Integer fileCount) {
        this.fileCount = fileCount;
    }

    public List<FileHash> getFileHashes() {
        return fileHashes;
    }

    public List<CVE> getCveList() {
        return cveList;
    }

    public List<Metadata> getMetadata() {
        return metadata;
    }

    public HashSet<String> getCveNames() {
        HashSet<String> cveSet = new HashSet<String>();
        for (CVE cve : getCveList()) {
            cveSet.add(cve.getName());
        }
        return cveSet;
    }
}