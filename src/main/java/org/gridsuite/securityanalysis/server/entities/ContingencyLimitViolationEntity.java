package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;

@Entity
@Table(name = "contingency_limit_violation")
public class ContingencyLimitViolationEntity extends LimitViolationEntity {
    @ManyToOne
    private ContingencyEntity contingency;
}
