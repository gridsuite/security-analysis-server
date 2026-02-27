/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.error;

import com.powsybl.ws.commons.error.PowsyblWsProblemDetail;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.gridsuite.securityanalysis.server.error.SecurityAnalysisBusinessErrorCode.CONTINGENCY_LIST_CONFIG_EMPTY;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
public class SecurityAnalysisExceptionHandlerTest {
    private SecurityAnalysisExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new SecurityAnalysisExceptionHandler(() -> "securityAnalysis");
    }

    @Test
    void mapsInteralErrorBusinessErrorToStatus() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/results-endpoint/uuid");
        SecurityAnalysisException exception = new SecurityAnalysisException(CONTINGENCY_LIST_CONFIG_EMPTY, "The configuration does not contain any contingency.");
        ResponseEntity<PowsyblWsProblemDetail> response = handler.handleSecurityAnalysisException(exception, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertEquals("securityAnalysis.contingencyListConfigEmpty", response.getBody().getBusinessErrorCode());
    }
}
