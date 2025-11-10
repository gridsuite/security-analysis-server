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
import lombok.experimental.FieldNameConstants;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldNameConstants
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

    public List<String> toCsvRow(Map<String, String> translations, String language) {
        if (this.getLimitViolation() == null) {
            return List.of();
        }
        List<String> csvRow = new ArrayList<>();
        csvRow.add(this.getSubjectId());
        csvRow.addAll(this.getLimitViolation().toCsvRow(translations, language));
        return csvRow;
    }
}
