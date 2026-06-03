/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.security.results.ConnectivityResult;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldNameConstants;

/**
 * @author Ghazwa Rehili <ghazwa.rehili at rte-france.com>
 */
@FieldNameConstants
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class ConnectivityResultEmbeddable {
    @Column(nullable = false)
    private double disconnectedLoadActivePower = 0.0;

    @Column(nullable = false)
    private double disconnectedGenerationActivePower = 0.0;

    public static ConnectivityResultEmbeddable toEntity(ConnectivityResult connectivityResult) {
        return ConnectivityResultEmbeddable.builder()
                .disconnectedGenerationActivePower(connectivityResult.getDisconnectedGenerationActivePower())
                .disconnectedLoadActivePower(connectivityResult.getDisconnectedLoadActivePower())
                .build();
    }
}
