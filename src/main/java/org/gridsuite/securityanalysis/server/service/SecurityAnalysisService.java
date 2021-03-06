/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.security.LimitViolationType;
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.repository.SecurityAnalysisResultRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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

    private SecurityAnalysisRunPublisherService runPublisherService;

    private SecurityAnalysisCancelPublisherService cancelPublisherService;

    private UuidGeneratorService uuidGeneratorService;

    public SecurityAnalysisService(SecurityAnalysisResultRepository resultRepository,
                                   SecurityAnalysisRunPublisherService runPublisherService,
                                   SecurityAnalysisCancelPublisherService cancelPublisherService,
                                   UuidGeneratorService uuidGeneratorService) {
        this.resultRepository = Objects.requireNonNull(resultRepository);
        this.runPublisherService = Objects.requireNonNull(runPublisherService);
        this.cancelPublisherService = Objects.requireNonNull(cancelPublisherService);
        this.uuidGeneratorService = Objects.requireNonNull(uuidGeneratorService);
    }

    public Mono<UUID> runAndSaveResult(SecurityAnalysisRunContext runContext) {
        Objects.requireNonNull(runContext);
        UUID resultUuid = uuidGeneratorService.generate();

        // update status to running status
        return setStatus(resultUuid, SecurityAnalysisStatus.RUNNING.name()).then(
                Mono.fromRunnable(() ->
                        runPublisherService.publish(new SecurityAnalysisResultContext(resultUuid, runContext)))
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
                cancelPublisherService.publish(new SecurityAnalysisCancelContext(resultUuid, receiver))).then();
    }
}
