/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.*;
import com.powsybl.security.LimitViolation;
import org.gridsuite.computation.utils.ComputationResultUtils;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;
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

    public static ContingencyLimitViolationEntity toEntity(@Nullable Network network, LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolation) {
        ContingencyLimitViolationEntityBuilder<?, ?> contingencyLimitViolationEntityBuilder = ContingencyLimitViolationEntity.builder()
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .limitType(limitViolation.getLimitType())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(computeLoading(limitViolation, limitViolation.getLimit()))
            .subjectLimitViolation(subjectLimitViolation)
            .upcomingAcceptableDuration(calculateUpcomingOverloadDuration(limitViolation));

        if (network != null) {
            enrichBuilderWithNetworkData(contingencyLimitViolationEntityBuilder, network, limitViolation);
        } else {
            enrichBuilderWithoutNetworkData(contingencyLimitViolationEntityBuilder);
        }

        ContingencyLimitViolationEntity contingencyLimitViolationEntity = contingencyLimitViolationEntityBuilder.build();

        subjectLimitViolation.addContingencyLimitViolation(contingencyLimitViolationEntity);

        return contingencyLimitViolationEntity;
    }

    private static void enrichBuilderWithNetworkData(ContingencyLimitViolationEntityBuilder<?, ?> contingencyLimitViolationEntityBuilder, Network network, LimitViolation limitViolation) {
        Double patlLimit = getPatlLimit(limitViolation, network);
        contingencyLimitViolationEntityBuilder
            .patlLimit(patlLimit)
            .patlLoading(computeLoading(limitViolation, patlLimit))
            .nextLimitName(getNextLimitName(limitViolation, network))
            .locationId(ComputationResultUtils.getViolationLocationId(limitViolation, network))
            .acceptableDuration(calculateActualOverloadDuration(limitViolation, network));
    }

    private static void enrichBuilderWithoutNetworkData(ContingencyLimitViolationEntityBuilder<?, ?> contingencyLimitViolationEntityBuilder) {
        // acceptable duration in not nullable
        contingencyLimitViolationEntityBuilder
            .acceptableDuration(0);
    }
}
