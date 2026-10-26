/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.contingency.violations.LimitViolation;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;
import org.gridsuite.computation.dto.securityanalysis.EnrichedLimitViolationDTO;
import org.gridsuite.computation.utils.ComputationResultUtils;
import org.springframework.lang.Nullable;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@NoArgsConstructor
@SuperBuilder
@Getter
@Entity
@FieldNameConstants
@EqualsAndHashCode(callSuper = true)
@Table(name = "contingency_limit_violation")
public class ContingencyLimitViolationEntity extends AbstractLimitViolationEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    private ContingencyEntity contingency;

    /**
     * Indicates whether this entity represents the worst side for its
     * SubjectLimitViolationEntity.subjectId + ContingencyEntity.contingencyId pair.
     * When multiple {@link ContingencyLimitViolationEntity} instances exist
     * for the same pair, the worst side is determined using the following
     * comparison rules, in order:
     * <ul>
     *   <li>Lowest acceptable duration (null is considered greater than any non-null value)</li>
     *   <li>Lowest upcoming acceptable duration (null is considered greater than any non-null value)</li>
     *   <li>Highest loading value (null is considered lower than any non-null value)</li>
     *   <li>Side alphabetical order</li>
     * </ul>
     *
     * If entities still cannot be distinguished after applying all criteria,
     * the entity with the lowest side value is considered the worst side.
     */
    @Setter
    private boolean isWorstSide;

    public static ContingencyLimitViolationEntity toEntity(LimitViolation limitViolation,
                                                           SubjectLimitViolationEntity subjectLimitViolation,
                                                           @Nullable EnrichedLimitViolationDTO enrichment) {
        ContingencyLimitViolationEntityBuilder<?, ?> contingencyLimitViolationEntityBuilder = ContingencyLimitViolationEntity.builder()
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .operationalLimitsGroupId(limitViolation.getOperationalLimitsGroupId())
            .limitType(limitViolation.getLimitType())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(ComputationResultUtils.computeLoading(limitViolation, limitViolation.getLimit()))
            .subjectLimitViolation(subjectLimitViolation)
            .upcomingAcceptableDuration(ComputationResultUtils.calculateUpcomingOverloadDuration(limitViolation));

        if (enrichment != null) {
            contingencyLimitViolationEntityBuilder
                .patlLimit(enrichment.getPatlLimit())
                .patlLoading(enrichment.getPatlLoading())
                .nextLimitName(enrichment.getNextLimitName())
                .locationId(enrichment.getLocationId())
                .acceptableDuration(enrichment.getAcceptableDuration());
        }

        ContingencyLimitViolationEntity contingencyLimitViolationEntity = contingencyLimitViolationEntityBuilder.build();

        subjectLimitViolation.addContingencyLimitViolation(contingencyLimitViolationEntity);

        return contingencyLimitViolationEntity;
    }
}
