/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.powsybl.security.SecurityAnalysis;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Component
public final class SecurityAnalysisUtil {

    private static String defaultProvider;

    @Value("${loadflow.default-provider:OpenSecurityAnalysis}")
    public void setDefaultProvider(String defaultProviderValue) {
        SecurityAnalysisUtil.defaultProvider = defaultProviderValue;
    }

    private SecurityAnalysisUtil() {
    }

    public static SecurityAnalysis.Runner getRunner(String provider) {
        if (provider != null) {
            return SecurityAnalysis.find(provider);
        } else {
            return SecurityAnalysis.find(defaultProvider);
        }
    }
}
