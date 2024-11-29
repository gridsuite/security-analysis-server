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
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.gridsuite.securityanalysis.server.util.SecurityAnalysisResultUtils.getIdFromViolation;

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

    public static List<PreContingencyLimitViolationEntity> toEntityList(PreContingencyResult preContingencyResult, Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId, Network network) {
        return preContingencyResult.getLimitViolationsResult().getLimitViolations().stream().map(limitViolation -> toEntity(limitViolation, subjectLimitViolationsBySubjectId.get(getIdFromViolation(limitViolation, network)))).collect(Collectors.toList());
    }

    public static PreContingencyLimitViolationEntity toEntity(LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolation) {
        return PreContingencyLimitViolationEntity.builder()
            .subjectLimitViolation(subjectLimitViolation)
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .limitType(limitViolation.getLimitType())
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(computeLoading(limitViolation))
            .build();
    }
}
