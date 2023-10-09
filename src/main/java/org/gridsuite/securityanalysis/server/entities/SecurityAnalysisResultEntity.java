package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "security_analysis_result")
public class SecurityAnalysisResultEntity {
    @Id
    private UUID id;

    @Setter
    private SecurityAnalysisStatus status;

    private String preContingencyStatus;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyEntity> contingencies;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PreContingencyLimitViolationEntity> preContingencyLimitViolations;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ConstraintEntity> constraints;

    public SecurityAnalysisResultEntity(UUID id) {
        this.id = id;
    }

    public SecurityAnalysisResultEntity(UUID id, SecurityAnalysisStatus status, String preContingencyStatus, List<ContingencyEntity> contingencies, List<PreContingencyLimitViolationEntity> preContingencyLimitViolations) {
        this.id = id;
        this.status = status;
        this.preContingencyStatus = preContingencyStatus;
        setContingencies(contingencies);
        setPreContingencyLimitViolations(preContingencyLimitViolations);

        // extracting unique constraints from all limit violations
        setConstraints(
            Stream.concat(
                this.contingencies.stream().flatMap(c -> c.getContingencyLimitViolations().stream()),
                this.preContingencyLimitViolations.stream()
            ).map(AbstractLimitViolationEntity::getConstraint)
            .distinct()
            .filter(Objects::nonNull)
            .collect(Collectors.toList())
        );
    }

    private void setContingencies(List<ContingencyEntity> contingencies) {
        if (contingencies != null) {
            this.contingencies = contingencies;
            this.contingencies.forEach(c -> c.setResult(this));
        }
    }

    private void setPreContingencyLimitViolations(List<PreContingencyLimitViolationEntity> preContingencyLimitViolations) {
        if (preContingencyLimitViolations != null) {
            this.preContingencyLimitViolations = preContingencyLimitViolations;
            this.preContingencyLimitViolations.forEach(lm -> lm.setResult(this));
        }
    }

    private void setConstraints(List<ConstraintEntity> constraints) {
        if (constraints != null) {
            this.constraints = constraints;
            constraints.forEach(constraint -> constraint.setResult(this));
        }
    }
}
