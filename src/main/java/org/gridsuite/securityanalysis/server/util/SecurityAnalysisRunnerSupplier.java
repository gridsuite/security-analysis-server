/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import com.powsybl.security.SecurityAnalysis;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Configuration
public class SecurityAnalysisRunnerSupplier {

    @Value("${loadflow.default-provider:OpenSecurityAnalysis}")
    private String defaultProvider;

    public SecurityAnalysis.Runner getRunner(String provider) {
        if (provider != null) {
            return SecurityAnalysis.find(provider);
        } else {
            return SecurityAnalysis.find(defaultProvider);
        }
    }
}
