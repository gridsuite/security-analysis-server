/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import com.powsybl.commons.PowsyblException;
import com.powsybl.openloadflow.sa.OpenSecurityAnalysisFactory;
import com.powsybl.security.SecurityAnalysisFactory;
import com.rte_france.powsybl.hades2.Hades2SecurityAnalysisFactory;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public final class SecurityAnalysisUtil {

    private SecurityAnalysisUtil() {
    }

    public static SecurityAnalysisFactory getFactory(String providerName) {
        if (providerName != null) {
            switch (providerName) {
                case "Hades2":
                    return new Hades2SecurityAnalysisFactory();
                case "OpenLoadFlow":
                    return new OpenSecurityAnalysisFactory();
                default:
                    throw new PowsyblException("Security analysis provider not found: " + providerName);
            }
        } else {
            return new OpenSecurityAnalysisFactory(); // open load flow by default
        }
    }
}
