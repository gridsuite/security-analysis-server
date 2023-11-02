/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.security.SecurityAnalysisProvider;
import org.gridsuite.securityanalysis.server.dto.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisService {
    private final SecurityAnalysisResultService securityAnalysisResultService;

    private final UuidGeneratorService uuidGeneratorService;

    private final NotificationService notificationService;

    private final ObjectMapper objectMapper;

    private final String defaultProvider;

    public SecurityAnalysisService(SecurityAnalysisResultService securityAnalysisResultService,
                                   UuidGeneratorService uuidGeneratorService,
                                   ObjectMapper objectMapper,
                                   NotificationService notificationService,
                                   @Value("${security-analysis.default-provider}") String defaultProvider) {
        this.securityAnalysisResultService = Objects.requireNonNull(securityAnalysisResultService);
        this.uuidGeneratorService = Objects.requireNonNull(uuidGeneratorService);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.notificationService = Objects.requireNonNull(notificationService);
        this.defaultProvider = Objects.requireNonNull(defaultProvider);
    }

    public UUID runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        var resultUuid = uuidGeneratorService.generate();
        // update status to running status
        setStatus(List.of(resultUuid), SecurityAnalysisStatus.RUNNING);
        notificationService.emitRunAnalysisMessage(new SecurityAnalysisResultContext(resultUuid, runContext).toMessage(objectMapper));

        return resultUuid;
    }

    public void deleteResult(UUID resultUuid) {
        securityAnalysisResultService.delete(resultUuid);
    }

    public void deleteResults() {
        securityAnalysisResultService.deleteAll();
    }

    public SecurityAnalysisStatus getStatus(UUID resultUuid) {
        return securityAnalysisResultService.findStatus(resultUuid);
    }

    public void setStatus(List<UUID> resultUuids, SecurityAnalysisStatus status) {
        securityAnalysisResultService.insertStatus(resultUuids, status);
    }

    public void stop(UUID resultUuid, String receiver) {
        notificationService.emitCancelAnalysisMessage(new SecurityAnalysisCancelContext(resultUuid, receiver).toMessage());
    }

    public List<String> getProviders() {
        return SecurityAnalysisProvider.findAll().stream()
                .map(SecurityAnalysisProvider::getName)
                .collect(Collectors.toList());
    }

    public String getDefaultProvider() {
        return defaultProvider;
    }
}
