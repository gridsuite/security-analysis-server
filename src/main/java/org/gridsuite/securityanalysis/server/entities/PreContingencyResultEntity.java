package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Embeddable
public class PreContingencyResultEntity {
    /**
     * We keep a String as it could model LoadFlowResult.ComponentResult.Status or PostContingencyComputationStatus.
     */
    private String status;

    @ElementCollection
    private List<PreContingencyLimitViolationEntity> preContingencyLimitViolation;
}
