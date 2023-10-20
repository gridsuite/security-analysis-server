/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.contingency.ContingencyElementType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyElementEmbeddable;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyElementDTO {
    private String id;
    private ContingencyElementType elementType;

    public static ContingencyElementDTO toDto(ContingencyElementEmbeddable contingencyElement) {
        return ContingencyElementDTO.builder()
            .id(contingencyElement.getElementId())
            .elementType(contingencyElement.getElementType())
            .build();
    }
}
