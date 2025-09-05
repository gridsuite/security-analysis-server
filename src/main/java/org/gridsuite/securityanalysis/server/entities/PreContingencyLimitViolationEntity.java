/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Network;
import com.powsybl.security.LimitViolation;
import com.powsybl.security.results.PreContingencyResult;
import org.gridsuite.computation.utils.ComputationResultUtils;
import jakarta.persistence.*;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Data
@NoArgsConstructor
@SuperBuilder
@Getter
@Entity
@FieldNameConstants
@Table(name = "pre_contingency_limit_violation")
public class PreContingencyLimitViolationEntity extends AbstractLimitViolationEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    SecurityAnalysisResultEntity result;

    public static List<PreContingencyLimitViolationEntity> toEntityList(Network network, PreContingencyResult preContingencyResult, Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId) {
        return preContingencyResult.getLimitViolationsResult().getLimitViolations().stream().map(limitViolation -> toEntity(network, limitViolation, subjectLimitViolationsBySubjectId.get(limitViolation.getSubjectId()))).collect(Collectors.toList());
    }

    public static PreContingencyLimitViolationEntity toEntity(Network network, LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolation) {
        return PreContingencyLimitViolationEntity.builder()
            .subjectLimitViolation(subjectLimitViolation)
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .limitType(limitViolation.getLimitType())
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(computeLoading(limitViolation, limitViolation.getLimit()))
            .locationId(ComputationResultUtils.getViolationLocationId(limitViolation, network))
            .build();
    }
}
