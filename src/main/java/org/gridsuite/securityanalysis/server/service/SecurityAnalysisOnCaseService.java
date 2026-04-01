/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisOnCaseService {
    private final SecurityAnalysisResultService securityAnalysisResultService;
    private final NotificationOnCaseService notificationOnCaseService;
    private final ObjectMapper objectMapper;
    private final String defaultProvider;

    public SecurityAnalysisOnCaseService(SecurityAnalysisResultService securityAnalysisResultService,
                                         NotificationOnCaseService notificationOnCaseService,
                                         ObjectMapper objectMapper,
                                         @Value("${security-analysis.default-provider}") String defaultProvider) {
        this.securityAnalysisResultService = securityAnalysisResultService;
        this.notificationOnCaseService = notificationOnCaseService;
        this.objectMapper = objectMapper;
        this.defaultProvider = defaultProvider;
    }

    @Transactional
    public void runAndSaveResult(UUID caseUuid, UUID executionUuid, List<String> contigencyListNames, UUID parametersUuid, UUID loadFlowParametersUuid) {
        notificationOnCaseService.sendMessage(
            new SecurityAnalysisCaseContext(caseUuid, executionUuid, contigencyListNames, parametersUuid, loadFlowParametersUuid).toMessage(objectMapper),
            "CaseRun-out-0");
    }
}
