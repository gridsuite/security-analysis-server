/**
 Copyright (c) 2024, RTE (http://www.rte-france.com)
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;

import java.util.ArrayList;
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

    private List<LimitReductionsByVoltageLevel> limitReductions;

    public SecurityAnalysisParametersEntity toEntity() {
        return new SecurityAnalysisParametersEntity(this);
    }

    @JsonIgnore
    public List<List<Double>> getLimitReductionsValues() {
        // Only for some providers
        return limitReductions == null ? null : limitReductions.stream().map(reductionsByVL -> {
            List<Double> values = new ArrayList<>(reductionsByVL.getTemporaryLimitReductions().size() + 1);
            values.add(reductionsByVL.getPermanentLimitReduction());
            reductionsByVL.getTemporaryLimitReductions().forEach(l -> values.add(l.getReduction()));
            return values;
        }).toList();
    }
}
