package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@NoArgsConstructor
@Entity
@Table(name = "contingency_limit_violation_constraint")
public class ConstraintEntity {
    public ConstraintEntity(String subjectId) {
        this.subjectId = subjectId;
    }

    @Id
    @GeneratedValue
    public UUID id;

    @Getter
    public String subjectId;

    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    @Getter
    private SecurityAnalysisResultEntity result;

    @Getter
    @OneToMany(mappedBy = "constraint")
    List<ContingencyLimitViolationEntity> contingencyLimitViolations;

    public void addContingencyLimitViolation(ContingencyLimitViolationEntity contingencyLimitViolation) {
        if (this.contingencyLimitViolations == null) {
            this.contingencyLimitViolations = new ArrayList<>();
        }
        this.contingencyLimitViolations.add(contingencyLimitViolation);
    }
}
