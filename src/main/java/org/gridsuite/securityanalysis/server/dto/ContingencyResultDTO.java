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
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class ContingencyResultDTO {
    private ContingencyDTO contingency;

    private List<SubjectLimitViolationDTO> subjectLimitViolations;

    public static ContingencyResultDTO toDto(ContingencyEntity contingency) {
        List<SubjectLimitViolationDTO> subjectLimitViolations = contingency.getContingencyLimitViolations().stream()
            .map(SubjectLimitViolationDTO::toDto)
            .toList();

        return ContingencyResultDTO.builder()
            .contingency(ContingencyDTO.toDto(contingency))
            .subjectLimitViolations(subjectLimitViolations)
            .build();
    }

    // each contingencyResultDto will return multiple line (one for each limitViolation)
    public List<List<String>> toCsvRows(Map<String, String> translations) {
        return this.getSubjectLimitViolations().stream().map(lm -> {
            List<String> csvRow = new ArrayList<>();
            csvRow.add(this.getContingency().getContingencyId());
            csvRow.add(CsvExportUtils.translate(this.getContingency().getStatus(), translations));
            csvRow.add(lm.getSubjectId());

            csvRow.addAll(lm.getLimitViolation().toCsvRow(translations));

            return csvRow;
        }).toList();

    }
}
