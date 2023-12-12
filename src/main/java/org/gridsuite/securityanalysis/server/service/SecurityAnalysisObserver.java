/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.service;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import lombok.NonNull;
import org.springframework.stereotype.Service;

/**
* @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
*/
@Service
public class SecurityAnalysisObserver {
    private final ObservationRegistry observationRegistry;

    private static final String OBSERVATION_PREFIX = "app.security-analysis.";
    private static final String PROVIDER_TAG_NAME = "provider";

    public SecurityAnalysisObserver(@NonNull ObservationRegistry observationRegistry) {
        this.observationRegistry = observationRegistry;
    }

    public <E extends Throwable> void observe(String name, SecurityAnalysisRunContext runContext, Observation.CheckedRunnable<E> callable) throws E {
        createSecurityAnalysisObservation(name, runContext).observeChecked(callable);
    }

    public <T, E extends Throwable> T observe(String name, SecurityAnalysisRunContext runContext, Observation.CheckedCallable<T, E> callable) throws E {
        return createSecurityAnalysisObservation(name, runContext).observeChecked(callable);
    }

    private Observation createSecurityAnalysisObservation(String name, SecurityAnalysisRunContext runContext) {
        return Observation.createNotStarted(OBSERVATION_PREFIX + name, observationRegistry)
            .lowCardinalityKeyValue(PROVIDER_TAG_NAME, runContext.getProvider());
    }
}
