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

import java.util.List;
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
}
