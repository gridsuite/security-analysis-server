/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.contingency.violations.LimitViolationType;
import com.powsybl.iidm.network.*;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;

import java.util.*;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@Getter
@FieldNameConstants
@MappedSuperclass
public abstract class AbstractLimitViolationEntity {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    private SubjectLimitViolationEntity subjectLimitViolation;

    @Column(name = "limitValue")
    private double limit;

    private Double patlLimit;

    private String limitName;

    private String operationalLimitsGroupId;

    private String nextLimitName;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private Integer acceptableDuration;

    private Integer upcomingAcceptableDuration;

    private double limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private ThreeSides side;

    @Column(name = "loading")
    private Double loading;

    private Double patlLoading;

    @Column
    private String locationId;
}
