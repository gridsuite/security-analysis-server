/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.error;

import com.powsybl.ws.commons.error.BusinessErrorCode;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
public enum SecurityAnalysisBusinessErrorCode implements BusinessErrorCode {
    CONTINGENCY_LIST_CONFIG_EMPTY("securityAnalysis.contingencyListConfigEmpty");

    private final String code;

    SecurityAnalysisBusinessErrorCode(String code) {
        this.code = code;
    }

    public String value() {
        return code;
    }
}
