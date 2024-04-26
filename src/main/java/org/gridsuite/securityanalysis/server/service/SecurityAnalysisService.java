/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisProvider;
import org.gridsuite.securityanalysis.server.computation.service.AbstractComputationService;
import org.gridsuite.securityanalysis.server.computation.service.NotificationService;
import org.gridsuite.securityanalysis.server.computation.service.UuidGeneratorService;
import org.gridsuite.securityanalysis.server.dto.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisService extends AbstractComputationService<SecurityAnalysisRunContext, SecurityAnalysisResultService, SecurityAnalysisStatus> {
    public static final String COMPUTATION_TYPE = "Security analysis";

    public SecurityAnalysisService(SecurityAnalysisResultService securityAnalysisResultService,
                                   UuidGeneratorService uuidGeneratorService,
                                   ObjectMapper objectMapper,
                                   NotificationService notificationService,
                                   @Value("${security-analysis.default-provider}") String defaultProvider) {
        super(notificationService, securityAnalysisResultService, objectMapper, uuidGeneratorService, defaultProvider);
    }

    public UUID runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        var resultUuid = uuidGeneratorService.generate();
        // update status to running status
        setStatus(List.of(resultUuid), SecurityAnalysisStatus.RUNNING);
        notificationService.sendRunMessage(new SecurityAnalysisResultContext(resultUuid, runContext).toMessage(objectMapper));

        return resultUuid;
    }

    public List<String> getProviders() {
        return SecurityAnalysisProvider.findAll().stream()
                .map(SecurityAnalysisProvider::getName)
                .toList();
    }

    public List<LimitViolationType> getLimitTypes(UUID resultUuid) {
        return resultService.findLimitTypes(resultUuid);
    }

    public List<ThreeSides> getBranchSides(UUID resultUuid) {
        return resultService.findBranchSides(resultUuid);
    }

    public List<com.powsybl.loadflow.LoadFlowResult.ComponentResult.Status> getComputationStatus(UUID resultUuid) {
        return resultService.findComputingStatus(resultUuid);
    }
}
