/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;
import org.gridsuite.computation.dto.securityanalysis.EnrichedLimitViolationDTO;
import org.gridsuite.computation.dto.securityanalysis.EnrichedPreContingencyResultDTO;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@SuperBuilder
@Getter
@Entity
@FieldNameConstants
@EqualsAndHashCode(callSuper = true)
@Table(name = "pre_contingency_limit_violation")
public class PreContingencyLimitViolationEntity extends AbstractLimitViolationEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    SecurityAnalysisResultEntity result;

    public static List<PreContingencyLimitViolationEntity> toEntityList(EnrichedPreContingencyResultDTO enrichedResult, Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId) {
        return enrichedResult.getEnrichedLimitViolations().stream().map(limitViolation ->
                toEntity(limitViolation, subjectLimitViolationsBySubjectId.get(limitViolation.getSubjectId()))).collect(Collectors.toList());
    }

    public static PreContingencyLimitViolationEntity toEntity(EnrichedLimitViolationDTO limitViolation, SubjectLimitViolationEntity subjectLimitViolation) {
        return PreContingencyLimitViolationEntity.builder()
            .subjectLimitViolation(subjectLimitViolation)
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .operationalLimitsGroupId(limitViolation.getOperationalLimitsGroupId())
            .limitType(limitViolation.getLimitType())
            .upcomingAcceptableDuration(limitViolation.getUpcomingAcceptableDuration())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(limitViolation.getLoading())
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .patlLimit(limitViolation.getPatlLimit())
            .patlLoading(limitViolation.getPatlLoading())
            .locationId(limitViolation.getLocationId())
            .nextLimitName(limitViolation.getNextLimitName())
            .build();
    }
}
