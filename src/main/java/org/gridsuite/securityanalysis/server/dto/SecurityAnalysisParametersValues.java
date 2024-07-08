/**
 Copyright (c) 2024, RTE (http://www.rte-france.com)
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import lombok.*;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;

import java.util.List;

/**
 * @author Abdelsalem Hedhili <abdelsalem.hedhili at rte-france.com>
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Builder
public class SecurityAnalysisParametersValues {
    private String provider;

    private double lowVoltageAbsoluteThreshold;

    private double lowVoltageProportionalThreshold;

    private double highVoltageAbsoluteThreshold;

    private double highVoltageProportionalThreshold;

    private double flowProportionalThreshold;

     // Only to set/get values from db
    private List<List<Double>> limitReductionsValues;

    @Setter
    private List<LimitReductionsByVoltageLevel> limitReductions;

    public SecurityAnalysisParametersEntity toEntity() {
        return new SecurityAnalysisParametersEntity(this);
    }
}
