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
import org.gridsuite.securityanalysis.server.entities.ConnectivityResultEmbeddable;

/**
 * @author Ghazwa Rehili <ghazwa.rehili at rte-france.com>
 */

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ConnectivityResultDTO {
    private Double disconnectedLoadActivePower;
    private Double disconnectedGenerationActivePower;

    public static ConnectivityResultDTO toDto(ConnectivityResultEmbeddable connectivityResult) {
        if (connectivityResult == null) {
            return ConnectivityResultDTO.builder()
                    .disconnectedLoadActivePower(null)
                    .disconnectedGenerationActivePower(null)
                    .build();
        }
        return ConnectivityResultDTO.builder()
                .disconnectedLoadActivePower(connectivityResult.getDisconnectedLoadActivePower())
                .disconnectedGenerationActivePower(connectivityResult.getDisconnectedGenerationActivePower())
                .build();
    }
}
