/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisService {
    private SecurityAnalysisResultRepository resultRepository;

    private UuidGeneratorService uuidGeneratorService;

    private NotificationService notificationService;

    private ObjectMapper objectMapper;

    private static final String CANCEL_CATEGORY_BROKER_OUTPUT = SecurityAnalysisService.class.getName() + ".output-broker-messages.cancel";

    private static final String RUN_CATEGORY_BROKER_OUTPUT = SecurityAnalysisService.class.getName() + ".output-broker-messages.run";

    public SecurityAnalysisService(SecurityAnalysisResultRepository resultRepository,
                                   UuidGeneratorService uuidGeneratorService,
                                   ObjectMapper objectMapper,
                                   NotificationService notificationService) {
        this.resultRepository = Objects.requireNonNull(resultRepository);
        this.uuidGeneratorService = Objects.requireNonNull(uuidGeneratorService);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.notificationService = Objects.requireNonNull(notificationService);
    }

    public Mono<UUID> runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        var resultUuid = uuidGeneratorService.generate();

        // update status to running status
        return setStatus(List.of(resultUuid), SecurityAnalysisStatus.RUNNING.name()).then(
                Mono.fromRunnable(() -> {
                    String parametersJson;
                    try {
                        parametersJson = objectMapper.writeValueAsString(runContext.getParameters());
                    } catch (JsonProcessingException e) {
                        throw new UncheckedIOException(e);
                    }
                    notificationService.emitRunAnalysisMessage(parametersJson, resultUuid.toString(), runContext);
                })
                .thenReturn(resultUuid));
    }

    public Mono<SecurityAnalysisResult> getResult(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        return Mono.fromCallable(() -> resultRepository.find(resultUuid, limitTypes));
    }

    public Mono<Void> deleteResult(UUID resultUuid) {
        return Mono.fromRunnable(() -> resultRepository.delete(resultUuid));
    }

    public Mono<Void> deleteResults() {
        return Mono.fromRunnable(() -> resultRepository.deleteAll());
    }

    public Mono<String> getStatus(UUID resultUuid) {
        return Mono.fromCallable(() -> resultRepository.findStatus(resultUuid));
    }

    public Mono<Void> setStatus(List<UUID> resultUuids, String status) {
        return Mono.fromRunnable(() -> resultRepository.insertStatus(resultUuids, status));
    }

    public Mono<Void> stop(UUID resultUuid, String receiver) {
        return Mono.fromRunnable(() -> notificationService.emitCancelAnalysisMessage(resultUuid.toString(), receiver)).then();
    }
}
