/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.contingency.violations.LimitViolation;
import com.powsybl.security.results.PreContingencyResult;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;
import org.gridsuite.computation.dto.securityanalysis.LimitViolationEnrichmentDTO;

import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

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

    public static List<PreContingencyLimitViolationEntity> toEntityList(PreContingencyResult preContingencyResult,
                                                                       Map<String, SubjectLimitViolationEntity> subjectLimitViolationsBySubjectId,
                                                                       List<LimitViolationEnrichmentDTO> preContingencyEnrichment) {
        List<LimitViolation> limitViolations = preContingencyResult.getLimitViolationsResult() == null
            ? List.of()
            : preContingencyResult.getLimitViolationsResult().getLimitViolations();
        return IntStream.range(0, limitViolations.size())
            .mapToObj(index -> {
                LimitViolation limitViolation = limitViolations.get(index);
                return toEntity(limitViolation,
                    subjectLimitViolationsBySubjectId.get(limitViolation.getSubjectId()),
                    preContingencyEnrichment.get(index));
            })
            .toList();
    }

    public static PreContingencyLimitViolationEntity toEntity(LimitViolation limitViolation,
                                                              SubjectLimitViolationEntity subjectLimitViolation,
                                                              LimitViolationEnrichmentDTO enrichment) {
        PreContingencyLimitViolationEntityBuilder<?, ?> preContingencyLimitViolationEntityBuilder = PreContingencyLimitViolationEntity.builder()
            .subjectLimitViolation(subjectLimitViolation)
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .operationalLimitsGroupId(limitViolation.getOperationalLimitsGroupId())
            .limitType(limitViolation.getLimitType())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(enrichment.getLoading())
            .upcomingAcceptableDuration(enrichment.getUpcomingAcceptableDuration())
            .acceptableDuration(enrichment.getAcceptableDuration())
            .patlLimit(enrichment.getPatlLimit())
            .patlLoading(enrichment.getPatlLoading())
            .locationId(enrichment.getLocationId())
            .nextLimitName(enrichment.getNextLimitName());

        return preContingencyLimitViolationEntityBuilder.build();
    }
}
