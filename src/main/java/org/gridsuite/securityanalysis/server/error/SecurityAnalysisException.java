/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.error;

import com.powsybl.ws.commons.error.AbstractBusinessException;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;

import java.util.Map;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Getter
public class SecurityAnalysisException extends AbstractBusinessException {
    private final SecurityAnalysisBusinessErrorCode errorCode;
    private final transient Map<String, Object> businessErrorValues;

    public SecurityAnalysisException(SecurityAnalysisBusinessErrorCode errorCode, String message) {
        this(errorCode, message, null);
    }

    public SecurityAnalysisException(SecurityAnalysisBusinessErrorCode errorCode, String message, Map<String, Object> businessErrorValues) {
        super(message);
        this.errorCode = errorCode;
        this.businessErrorValues = businessErrorValues != null ? Map.copyOf(businessErrorValues) : Map.of();
    }

    @NotNull
    @Override
    public SecurityAnalysisBusinessErrorCode getBusinessErrorCode() {
        return errorCode;
    }
}
