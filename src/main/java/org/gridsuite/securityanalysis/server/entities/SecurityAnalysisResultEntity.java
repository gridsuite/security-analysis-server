package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "security_analysis_result")
public class SecurityAnalysisResultEntity {
    @Id
    private UUID id;

    @Setter
    private SecurityAnalysisStatus status;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyEntity> contingencies;

    @OneToMany(mappedBy = "result", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ContingencyLimitViolationEntity> contingencyLimitViolation;

    @Embedded
    private PreContingencyResultEntity preContingencyResult;

    public SecurityAnalysisResultEntity(UUID id, SecurityAnalysisStatus status, List<ContingencyEntity> contingencies, PreContingencyResultEntity preContingencyResult) {
        this.id = id;
        this.status = status;
        this.preContingencyResult = preContingencyResult;
        setContingencies(contingencies);
    }

    private void setContingencies(List<ContingencyEntity> contingencies) {
        if (contingencies != null) {
            this.contingencies = contingencies;
            this.contingencyLimitViolation = contingencies.stream().flatMap(c -> c.getContingencyLimitViolations().stream()).collect(Collectors.toList());
            this.contingencies.forEach(c -> c.setResult(this));
            this.contingencyLimitViolation.forEach(lm -> lm.setResult(this));
        }
    }
}
