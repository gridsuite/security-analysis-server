/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import com.powsybl.security.SecurityAnalysis;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public final class SecurityAnalysisUtil {

    private SecurityAnalysisUtil() {
    }

    public static SecurityAnalysis.Runner getRunner(String provider) {
        if (provider != null) {
            return SecurityAnalysis.find(provider);
        } else {
            return SecurityAnalysis.find("OpenSecurityAnalysis"); // open load flow by default
        }
    }
}
