/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.error;

import com.powsybl.ws.commons.error.AbstractBusinessExceptionHandler;
import com.powsybl.ws.commons.error.PowsyblWsProblemDetail;
import com.powsybl.ws.commons.error.ServerNameProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@ControllerAdvice
public class SecurityAnalysisExceptionHandler
        extends AbstractBusinessExceptionHandler<SecurityAnalysisException, SecurityAnalysisBusinessErrorCode> {

    public SecurityAnalysisExceptionHandler(ServerNameProvider serverNameProvider) {
        super(serverNameProvider);
    }

    @NonNull
    @Override
    protected SecurityAnalysisBusinessErrorCode getBusinessCode(SecurityAnalysisException ex) {
        return ex.getBusinessErrorCode();
    }

    @Override
    protected HttpStatus mapStatus(SecurityAnalysisBusinessErrorCode errorCode) {
        return switch (errorCode) {
            case CONTINGENCY_LIST_CONFIG_EMPTY -> HttpStatus.BAD_REQUEST;
        };
    }

    @ExceptionHandler(SecurityAnalysisException.class)
    protected ResponseEntity<PowsyblWsProblemDetail> handleSecurityAnalysisException(
            SecurityAnalysisException exception, HttpServletRequest request) {
        return super.handleDomainException(exception, request);
    }
}
