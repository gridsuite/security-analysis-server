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

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Data
@NoArgsConstructor
@SuperBuilder
@Getter
@Entity
@FieldNameConstants
@Table(name = "contingency_limit_violation")
public class ContingencyLimitViolationEntity extends AbstractLimitViolationEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    private ContingencyEntity contingency;

    public static ContingencyLimitViolationEntity toEntity(Network network, LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolation) {
        Double patlLimit = getPatlLimit(limitViolation, network);

        ContingencyLimitViolationEntity contingencyLimitViolationEntity = ContingencyLimitViolationEntity.builder()
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .limitType(limitViolation.getLimitType())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .loading(computeLoading(limitViolation, limitViolation.getLimit()))
            .locationId(ComputationResultUtils.getViolationLocationId(limitViolation, network))
            .subjectLimitViolation(subjectLimitViolation)
            .patlLimit(patlLimit)
            .patlLoading(computeLoading(limitViolation, patlLimit))
            .nextLimitName(getNextLimitName(limitViolation, network))
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .build();

        subjectLimitViolation.addContingencyLimitViolation(contingencyLimitViolationEntity);

        return contingencyLimitViolationEntity;
    }
}
