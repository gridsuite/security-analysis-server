/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.repository.SecurityAnalysisResultRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.*;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisService {
    private SecurityAnalysisResultRepository resultRepository;

    private UuidGeneratorService uuidGeneratorService;

    private ObjectMapper objectMapper;

    @Autowired
    private StreamBridge cancelMessagePublisher;

    @Autowired
    private StreamBridge runMessagePublisher;

    public SecurityAnalysisService(SecurityAnalysisResultRepository resultRepository,
                                   UuidGeneratorService uuidGeneratorService, ObjectMapper objectMapper) {
        this.resultRepository = Objects.requireNonNull(resultRepository);
        this.uuidGeneratorService = Objects.requireNonNull(uuidGeneratorService);
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    public Mono<UUID> runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        var resultUuid = uuidGeneratorService.generate();

        // update status to running status
        return setStatus(resultUuid, SecurityAnalysisStatus.RUNNING.name()).then(
                Mono.fromRunnable(() ->
                        runMessagePublisher.send("publishRun-out-0", new SecurityAnalysisResultContext(resultUuid, runContext).toMessage(objectMapper)))
                .thenReturn(resultUuid));
    }

    public Mono<SecurityAnalysisResult> getResult(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        return resultRepository.find(resultUuid, limitTypes);
    }

    public Mono<Void> deleteResult(UUID resultUuid) {
        return resultRepository.delete(resultUuid);
    }

    public Mono<Void> deleteResults() {
        return resultRepository.deleteAll();
    }

    public Mono<String> getStatus(UUID resultUuid) {
        return resultRepository.findStatus(resultUuid);
    }

    public Mono<Void> setStatus(UUID resultUuid, String status) {
        return resultRepository.insertStatus(resultUuid, status);
    }

    public Mono<Void> stop(UUID resultUuid, String receiver) {
        return Mono.fromRunnable(() ->
                cancelMessagePublisher.send("publishCancel-out-0", new SecurityAnalysisCancelContext(resultUuid, receiver).toMessage())).then();
    }
}
