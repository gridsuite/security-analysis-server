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

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

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
        List<String> csvRow = List.of();

        if (this.getLimitViolation() != null) {
            csvRow = List.of(this.getSubjectId());
            return Stream.concat(csvRow.stream(), this.getLimitViolation().toCsvRow(translations, language).stream()).toList();
        }

        return csvRow;
    }
}
