package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

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
        this.contingencyLimitViolations = contingencyLimitViolations;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID uuid;

    private String contingencyId;

    @ManyToOne(fetch = FetchType.LAZY, cascade = CascadeType.ALL)
    private SecurityAnalysisResultEntity result;

    @ElementCollection
    private List<ContingencyElementEmbeddable> contingencyElements;

    @OneToMany(mappedBy = "contingency")
    List<ContingencyLimitViolationEntity> contingencyLimitViolations;

    /**
     * We keep a String as it could model LoadFlowResult.ComponentResult.Status or PostContingencyComputationStatus.
     */
    private String status;
}
