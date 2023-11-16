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

import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Getter
@MappedSuperclass
public abstract class AbstractLimitViolationEntity {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne
    private SubjectLimitViolationEntity subjectLimitViolation;

    @Column(name = "limitValue")
    private double limit;

    private String limitName;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private long acceptableDuration;

    private float limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private Branch.Side side;

    @Column(name = "loading")
    private Double loading;

    public static Double computeLoading(LimitViolation limitViolation) {
        return LimitViolationType.CURRENT.equals(limitViolation.getLimitType())
                ? (100 * limitViolation.getValue()) / (limitViolation.getLimit() * limitViolation.getLimitReduction())
                : null;
    }
}
