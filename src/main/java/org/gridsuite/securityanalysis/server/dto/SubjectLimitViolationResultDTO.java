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
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SubjectLimitViolationResultDTO {
    private String subjectId;

    private List<ContingencyLimitViolationDTO> contingencies;

    public static SubjectLimitViolationResultDTO toDto(SubjectLimitViolationEntity subjectLimitViolation) {
        List<ContingencyLimitViolationDTO> contingencies = subjectLimitViolation.getContingencyLimitViolations().stream()
            .map(ContingencyLimitViolationDTO::toDto)
            .toList();

        return SubjectLimitViolationResultDTO.builder()
            .subjectId(subjectLimitViolation.getSubjectId())
            .contingencies(contingencies)
            .build();
    }

    // each SubjectLimitViolationResultDTO will return multiple line (one for each contingency)
    public List<List<String>> toCsvRows() {
        List<List<String>> csvRows = new ArrayList<>();
        this.getContingencies().forEach(contingency -> {
            List<String> csvRow = new ArrayList<>();
            csvRow.add(this.getSubjectId());
            csvRow.add(contingency.getContingency().getContingencyId());
            csvRow.add(contingency.getContingency().getStatus());

            csvRows.add(Stream.concat(csvRow.stream(), contingency.getLimitViolation().toCsvRow().stream()).toList());
        });

        return csvRows;
    }
}
