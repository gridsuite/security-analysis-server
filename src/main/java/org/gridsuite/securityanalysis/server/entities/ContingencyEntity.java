package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "contingency")
public class ContingencyEntity {

    public ContingencyEntity(String contingencyId, String status, List<ContingencyElementEmbeddable> contingencyElements, List<ContingencyLimitViolationEntity> contingencyLimitViolations) {
        this.contingencyId = contingencyId;
        this.status = status;
        this.contingencyElements = contingencyElements;
        setContingencyLimitViolations(contingencyLimitViolations);
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID uuid;

    private String contingencyId;

    @Setter
    @ManyToOne(fetch = FetchType.LAZY)
    private SecurityAnalysisResultEntity result;

    @ElementCollection
    private List<ContingencyElementEmbeddable> contingencyElements;

    @OneToMany(mappedBy = "contingency")
    List<ContingencyLimitViolationEntity> contingencyLimitViolations;

    /**
     * We keep a String as it could model LoadFlowResult.ComponentResult.Status or PostContingencyComputationStatus.
     */
    private String status;

    private void setContingencyLimitViolations(List<ContingencyLimitViolationEntity> contingencyLimitViolations) {
        if (contingencyLimitViolations != null) {
            this.contingencyLimitViolations = contingencyLimitViolations;
            contingencyLimitViolations.forEach(lm -> lm.setContingency(this));
        }
    }
}
