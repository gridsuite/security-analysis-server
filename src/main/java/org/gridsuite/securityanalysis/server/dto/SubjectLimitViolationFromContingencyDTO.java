/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class SubjectLimitViolationFromContingencyDTO {
    private String subjectId;
    private LimitViolationType limitType;
    private String limitName;
    private Branch.Side side;
    private int acceptableDuration;
    private double limit;
    private double limitReduction;
    private double value;
    private Double loading;

    public SubjectLimitViolationFromContingencyDTO(String subjectId, LimitViolationType limitType, String limitName, Branch.Side side, int acceptableDuration, double limit, double limitReduction, double value) {
        this.subjectId = subjectId;
        this.limitType = limitType;
        this.limitName = limitName;
        this.side = side;
        this.acceptableDuration = acceptableDuration;
        this.limit = limit;
        this.limitReduction = limitReduction;
        this.value = value;

        Double computedLoading = LimitViolationType.CURRENT.equals(limitType)
            ? (100 * value) / (limit * limitReduction)
            : null;

        this.loading = computedLoading;
    }

    public static SubjectLimitViolationFromContingencyDTO toDto(ContingencyLimitViolationEntity limitViolation) {
        String subjectId = limitViolation.getSubjectLimitViolation() != null
            ? limitViolation.getSubjectLimitViolation().getSubjectId()
            : null;

        return new SubjectLimitViolationFromContingencyDTO(subjectId, limitViolation.getLimitType(), limitViolation.getLimitName(), limitViolation.getSide(), limitViolation.getAcceptableDuration(), limitViolation.getLimit(), limitViolation.getLimitReduction(), limitViolation.getValue());
    }
}
