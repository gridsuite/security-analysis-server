/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
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
import java.util.stream.Collectors;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class ContingencyDTO {
    private String contingencyId;
    private String status;
    private List<ContingencyElementDTO> elements;
    private ConnectivityResultDTO connectivityResult;

    public static ContingencyDTO toDto(ContingencyEntity contingency) {
        return ContingencyDTO.builder()
            .contingencyId(contingency.getContingencyId())
            .status(contingency.getStatus())
            .elements(contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).collect(Collectors.toList()))
            .connectivityResult(ConnectivityResultDTO.toDto(contingency.getConnectivityResult()))
            .build();
    }
}
