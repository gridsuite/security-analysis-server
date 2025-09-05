/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.*;
import com.powsybl.iidm.network.util.LimitViolationUtils;
import com.powsybl.security.LimitViolation;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;

import java.util.Collection;
import java.util.Iterator;
import java.util.Optional;
import java.util.UUID;

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

    private String nextLimitName;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private long acceptableDuration;

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

    protected static Double computeLoading(LimitViolation limitViolation, Double limit) {
        return LimitViolationType.CURRENT.equals(limitViolation.getLimitType()) && limit != null
                ? 100 * limitViolation.getValue() / limit
                : null;
    }

    protected static Double getPatlLimit(LimitViolation limitViolation, Network network) {
        String equipmentId = limitViolation.getSubjectId();
        Branch<?> branch = network.getBranch(equipmentId);
        ThreeSides limitViolationSide = limitViolation.getSide();
        if (branch == null || limitViolationSide == null) {
            return null;
        }

        Optional<CurrentLimits> currentLimits = branch.getCurrentLimits(limitViolationSide.toTwoSides());
        if (currentLimits.isPresent()) {
            return currentLimits.get().getPermanentLimit();
        }
        return null;
    }

    protected static String getNextLimitName(LimitViolation limitViolation, Network network) {
        String equipmentId = limitViolation.getSubjectId();
        Branch<?> branch = network.getBranch(equipmentId);
        if (branch == null) {
            return null;
        }
        LoadingLimits.TemporaryLimit temporaryLimit = getNextTemporaryLimit(branch, limitViolation);
        return temporaryLimit != null ? temporaryLimit.getName() : null;
    }

    private static LoadingLimits.TemporaryLimit getNextTemporaryLimit(Branch<?> branch, LimitViolation limitViolation) {
        // limits are returned from the store by DESC duration / ASC value
        ThreeSides limitViolationSide = limitViolation.getSide();
        String limitName = limitViolation.getLimitName();
        if (limitViolationSide == null || limitName == null) {
            return null;
        }

        Optional<CurrentLimits> currentLimits = branch.getCurrentLimits(limitViolationSide.toTwoSides());
        if (currentLimits.isEmpty()) {
            return null;
        }

        Collection<LoadingLimits.TemporaryLimit> temporaryLimits = currentLimits.get().getTemporaryLimits();
        if (limitName.equals(LimitViolationUtils.PERMANENT_LIMIT_NAME)) {
            return temporaryLimits.stream().findFirst().orElse(null);
        }

        Iterator<LoadingLimits.TemporaryLimit> temporaryLimitIterator = temporaryLimits.iterator();
        while (temporaryLimitIterator.hasNext()) {
            LoadingLimits.TemporaryLimit currentTemporaryLimit = temporaryLimitIterator.next();
            if (currentTemporaryLimit.getName().equals(limitViolation.getLimitName())) {
                return temporaryLimitIterator.hasNext() ? temporaryLimitIterator.next() : null;
            }
        }

        return null;
    }
}
