/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.security.SecurityAnalysisProvider;
import com.powsybl.security.results.PreContingencyResult;
import org.gridsuite.securityanalysis.server.dto.ConstraintToContingencyDTO;
import org.gridsuite.securityanalysis.server.dto.ContingencyToConstraintDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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
    private final SecurityAnalysisResultService resultRepository;

    private final UuidGeneratorService uuidGeneratorService;

    private final NotificationService notificationService;

    private final ObjectMapper objectMapper;

    private final String defaultProvider;

    public SecurityAnalysisService(SecurityAnalysisResultService resultRepository,
                                   UuidGeneratorService uuidGeneratorService,
                                   ObjectMapper objectMapper,
                                   NotificationService notificationService,
                                   @Value("${security-analysis.default-provider}") String defaultProvider) {
        this.resultRepository = Objects.requireNonNull(resultRepository);
        this.uuidGeneratorService = Objects.requireNonNull(uuidGeneratorService);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.notificationService = Objects.requireNonNull(notificationService);
        this.defaultProvider = Objects.requireNonNull(defaultProvider);
    }

    public Mono<UUID> runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        var resultUuid = uuidGeneratorService.generate();

        // update status to running status
        return setStatus(List.of(resultUuid), SecurityAnalysisStatus.RUNNING).then(
                Mono.fromRunnable(() ->
                    notificationService.emitRunAnalysisMessage(new SecurityAnalysisResultContext(resultUuid, runContext).toMessage(objectMapper))
                )
                .thenReturn(resultUuid));
    }

    public Mono<PreContingencyResult> getNResult(UUID resultUuid) {
        return Mono.fromCallable(() -> resultRepository.findNResult(resultUuid));
    }

    public Mono<List<ContingencyToConstraintDTO>> getNmKContingenciesResult(UUID resultUuid) {
        return Mono.fromCallable(() -> resultRepository.findNmKContingenciesResult(resultUuid));
    }

    public Mono<List<ConstraintToContingencyDTO>> getNmKConstraintsResult(UUID resultUuid) {
        return Mono.fromCallable(() -> resultRepository.findNmKConstraintsResult(resultUuid));
    }

    public Mono<Void> deleteResult(UUID resultUuid) {
        return Mono.fromRunnable(() -> resultRepository.delete(resultUuid));
    }

    public Mono<Void> deleteResults() {
        return Mono.fromRunnable(() -> resultRepository.deleteAll());
    }

    public Mono<SecurityAnalysisStatus> getStatus(UUID resultUuid) {
        return Mono.fromCallable(() -> resultRepository.findStatus(resultUuid));
    }

    public Mono<Void> setStatus(List<UUID> resultUuids, SecurityAnalysisStatus status) {
        return Mono.fromRunnable(() -> resultRepository.insertStatus(resultUuids, status));
    }

    public Mono<Void> stop(UUID resultUuid, String receiver) {
        return Mono.fromRunnable(() -> notificationService.emitCancelAnalysisMessage(new SecurityAnalysisCancelContext(resultUuid, receiver).toMessage())).then();
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
