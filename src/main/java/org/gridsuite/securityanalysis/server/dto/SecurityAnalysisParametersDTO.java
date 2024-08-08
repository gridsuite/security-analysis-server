/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.security.SecurityAnalysisParameters;
import lombok.Builder;

import java.util.List;

@Builder
public record SecurityAnalysisParametersDTO(
        SecurityAnalysisParameters securityAnalysisParameters,
        List<List<Double>> limitReductions
) { }
