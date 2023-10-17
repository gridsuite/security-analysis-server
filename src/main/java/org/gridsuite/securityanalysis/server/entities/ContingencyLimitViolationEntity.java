/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolation;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Data
@NoArgsConstructor
@SuperBuilder
@Getter
@Entity
@Table(name = "contingency_limit_violation")
public class ContingencyLimitViolationEntity extends AbstractLimitViolationEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    private ContingencyEntity contingency;

    public static ContingencyLimitViolationEntity toEntity(LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolation) {
        ContingencyLimitViolationEntity contingencyLimitViolationEntity = ContingencyLimitViolationEntity.builder()
            .limit(limitViolation.getLimit())
            .limitName(limitViolation.getLimitName())
            .limitType(limitViolation.getLimitType())
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .side(limitViolation.getSide())
            .subjectLimitViolation(subjectLimitViolation)
            .build();

        subjectLimitViolation.addContingencyLimitViolation(contingencyLimitViolationEntity);

        return contingencyLimitViolationEntity;
    }
}
