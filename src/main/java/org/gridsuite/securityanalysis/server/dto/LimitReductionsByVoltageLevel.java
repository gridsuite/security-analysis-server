/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import lombok.*;

import java.util.List;

@Data
@Builder
public class LimitReductionsByVoltageLevel {

    @Setter
    @Getter
    public static class LimitDuration {
        private Integer lowBound;
        private boolean lowClosed;
        private Integer highBound;
        private boolean highClosed;
    }

    @Setter
    @Getter
    public static class VoltageLevel {
        private double nominalV;
        private double lowBound;
        private double highBound;
    }

    @Builder
    @Setter
    @Getter
    public static class LimitReduction {
        double reduction;
        LimitDuration limitDuration;
    }

    private VoltageLevel voltageLevel;
    private double permanentLimitReduction;
    List<LimitReduction> temporaryLimitReductions;
}
