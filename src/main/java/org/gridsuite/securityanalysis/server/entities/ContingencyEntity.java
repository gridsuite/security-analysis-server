/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Network;
import com.powsybl.security.results.PostContingencyResult;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;
import org.springframework.lang.Nullable;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@Getter
@Entity
@FieldNameConstants
@Table(name = "contingency")
public class ContingencyEntity {

    public ContingencyEntity(String contingencyId, String status, List<ContingencyElementEmbeddable> contingencyElements, ConnectivityResultEntity connectivityResult, List<ContingencyLimitViolationEntity> contingencyLimitViolations) {
        this.contingencyId = contingencyId;
        this.status = status;
        this.contingencyElements = contingencyElements;
        this.connectivityResult = connectivityResult;
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

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true)
    @JoinColumn(name = "connectivity_result_id", foreignKey = @ForeignKey(name = "contingency_connectivity_result_id_fk"))
    private ConnectivityResultEntity connectivityResult;

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

    public static ContingencyEntity toEntity(@Nullable Network network, PostContingencyResult postContingencyResult, Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId) {
        List<ContingencyElementEmbeddable> contingencyElements = postContingencyResult.getContingency().getElements().stream().map(contingencyElement -> ContingencyElementEmbeddable.toEntity(contingencyElement)).collect(Collectors.toList());

        List<ContingencyLimitViolationEntity> contingencyLimitViolations = postContingencyResult.getLimitViolationsResult().getLimitViolations().stream()
            .map(limitViolation -> ContingencyLimitViolationEntity.toEntity(network, limitViolation, subjectLimitViolationsBySubjectId.get(limitViolation.getSubjectId())))
            .collect(Collectors.toList());
        ConnectivityResultEntity connectivityResult = postContingencyResult.getConnectivityResult() != null
            ? ConnectivityResultEntity.toEntity(postContingencyResult.getConnectivityResult())
            : null;
        return new ContingencyEntity(postContingencyResult.getContingency().getId(), postContingencyResult.getStatus().name(), contingencyElements, connectivityResult, contingencyLimitViolations);
    }
}
