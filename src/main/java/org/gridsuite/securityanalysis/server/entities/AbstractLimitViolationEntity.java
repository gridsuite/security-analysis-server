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
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@Getter
@MappedSuperclass
public abstract class AbstractLimitViolationEntity {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne
    private ConstraintEntity constraint;

    private String subjectName;

    @Column(name = "limitValue")
    private double limit;

    private String limitName;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private int acceptableDuration;

    private float limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private Branch.Side side;

    protected AbstractLimitViolationEntity(ConstraintEntity constraint, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        this.constraint = constraint;
        this.subjectName = subjectName;
        this.limit = limit;
        this.limitName = limitName;
        this.limitType = limitType;
        this.acceptableDuration = acceptableDuration;
        this.limitReduction = limitReduction;
        this.value = value;
        this.side = side;
    }

    public static LimitViolation fromEntity(AbstractLimitViolationEntity limitViolationEntity) {
        String subjectId = limitViolationEntity.getConstraint() != null
            ? limitViolationEntity.getConstraint().getSubjectId()
            : null;

        return new LimitViolation(subjectId, limitViolationEntity.getLimitType(), limitViolationEntity.getLimitName(), limitViolationEntity.getAcceptableDuration(),
            limitViolationEntity.getLimit(), limitViolationEntity.getLimitReduction(), limitViolationEntity.getValue(), limitViolationEntity.getSide());
    }
}
