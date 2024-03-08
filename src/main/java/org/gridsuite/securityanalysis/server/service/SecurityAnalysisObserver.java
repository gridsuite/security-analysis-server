/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.service;

import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisResult;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import lombok.NonNull;
import org.gridsuite.securityanalysis.server.computation.service.AbstractComputationObserver;
import org.springframework.stereotype.Service;

/**
* @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
*/
@Service
public class SecurityAnalysisObserver extends AbstractComputationObserver<SecurityAnalysisResult, SecurityAnalysisParameters> {

    private static final String COMPUTATION_TYPE = "sa";

    public SecurityAnalysisObserver(@NonNull ObservationRegistry observationRegistry, @NonNull MeterRegistry meterRegistry) {
        super(observationRegistry, meterRegistry);
    }

    @Override
    protected String getComputationType() {
        return COMPUTATION_TYPE;
    }

    @Override
    protected String getResultStatus(SecurityAnalysisResult res) {
        return res != null && res.getPreContingencyResult().getStatus() == LoadFlowResult.ComponentResult.Status.CONVERGED ? "OK" : "NOK";
    }
}
