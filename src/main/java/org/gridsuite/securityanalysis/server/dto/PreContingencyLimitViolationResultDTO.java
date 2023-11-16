/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PreContingencyLimitViolationResultDTO {

    private String subjectId;
    private String status;
    private LimitViolationDTO limitViolation;

    public static PreContingencyLimitViolationResultDTO toDto(PreContingencyLimitViolationEntity preContingencyLimitViolation) {
        String subjectId = preContingencyLimitViolation.getSubjectLimitViolation() != null
                ? preContingencyLimitViolation.getSubjectLimitViolation().getSubjectId()
                : null;

        return PreContingencyLimitViolationResultDTO.builder()
                .subjectId(subjectId)
                .status(preContingencyLimitViolation.getResult().getPreContingencyStatus())
                .limitViolation(LimitViolationDTO.toDto(preContingencyLimitViolation))
                .build();
    }
}
