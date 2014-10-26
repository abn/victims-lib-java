package com.redhat.victims.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import javax.persistence.UniqueConstraint;
import javax.validation.constraints.NotNull;

/**
 * Created by abn on 10/25/14.
 */
@Entity
@Table(uniqueConstraints = @UniqueConstraint(columnNames = "status"))
public class Status {

    @Id
    private String status;

    @NotNull
    @Column
    private String value;

    public Status() {

    }


    public Status(String status, String value) {
        this.status = status;
        this.value = value;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Created by abn on 10/25/14.
     */
    public static enum StatusKey {
        LAST_UPDATED
    }
}
