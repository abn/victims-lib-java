package com.redhat.victims.database.model;

import java.util.HashSet;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
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

    @OneToMany(cascade = CascadeType.ALL)
    @JoinColumn(name = "record_id")
    private Set<FileHash> filehashes;

    @OneToMany(cascade = CascadeType.ALL)
    @JoinColumn(name = "record_id")
    private Set<CVE> cves;

    @OneToMany(cascade = CascadeType.ALL)
    @JoinColumn(name = "record_id")
    private Set<Metadata> metadata;

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

    public Set<FileHash> getFilehashes() {
        return filehashes;
    }

    public Set<CVE> getCves() {
        return cves;
    }

    public Set<Metadata> getMetadata() {
        return metadata;
    }

    public HashSet<String> getCveNames() {
        HashSet<String> cves = new HashSet<String>();
        for (CVE cve : getCves()) {
            cves.add(cve.getCve());
        }
        return cves;
    }
}