/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;
import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

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

    @OneToMany(mappedBy = "contingency", cascade = CascadeType.ALL, orphanRemoval = true)
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
