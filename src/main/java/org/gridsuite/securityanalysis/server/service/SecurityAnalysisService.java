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
import org.gridsuite.computation.service.AbstractComputationService;
import org.gridsuite.computation.service.NotificationService;
import org.gridsuite.computation.service.UuidGeneratorService;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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

    @Override
    @Transactional
    public UUID runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        var resultUuid = uuidGeneratorService.generate();
        // update status to running status
        setStatus(List.of(resultUuid), SecurityAnalysisStatus.RUNNING);
        notificationService.sendRunMessage(new SecurityAnalysisResultContext(resultUuid, runContext).toMessage(objectMapper));

        return resultUuid;
    }

    @Override
    public List<String> getProviders() {
        return SecurityAnalysisProvider.findAll().stream()
            .map(SecurityAnalysisProvider::getName)
            .toList();
    }

    public List<LimitViolationType> getNResultLimitTypes(UUID resultUuid) {
        return resultService.findNResultLimitTypes(resultUuid);
    }

    public List<LimitViolationType> getNmKResultLimitTypes(UUID resultUuid) {
        return resultService.findNmKResultLimitTypes(resultUuid);
    }

    public List<ThreeSides> getNResultBranchSides(UUID resultUuid) {
        return resultService.findNResultBranchSides(resultUuid);
    }

    public List<ThreeSides> getNmKResultBranchSides(UUID resultUuid) {
        return resultService.findNmKResultBranchSides(resultUuid);
    }

    public List<com.powsybl.loadflow.LoadFlowResult.ComponentResult.Status> getNmKComputationStatus(UUID resultUuid) {
        return resultService.findNmKComputingStatus(resultUuid);
    }
}
