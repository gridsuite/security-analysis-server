/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.contingency.GeneratorContingency;
import com.powsybl.security.*;
import org.gridsuite.securityanalysis.server.repository.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisService.class);

    private ComputationStatusRepository computationStatusRepository;

    private ContingencyRepository contingencyRepository;

    private LimitViolationRepository limitViolationRepository;

    private SecurityAnalysisRunPublisherService runPublisher;

    public SecurityAnalysisService(ComputationStatusRepository computationStatusRepository, ContingencyRepository contingencyRepository,
                                   LimitViolationRepository limitViolationRepository, SecurityAnalysisRunPublisherService runPublisher) {
        this.computationStatusRepository = Objects.requireNonNull(computationStatusRepository);
        this.contingencyRepository = Objects.requireNonNull(contingencyRepository);
        this.limitViolationRepository = Objects.requireNonNull(limitViolationRepository);
        this.runPublisher = Objects.requireNonNull(runPublisher);
    }

    public UUID generateResultUuid() {
        return UUID.randomUUID();
    }

    public Mono<UUID> runAndSave(SecurityAnalysisRunContext context) {
        Objects.requireNonNull(context);
        UUID resultUuid = generateResultUuid();
        runPublisher.publish(resultUuid, context);
        return Mono.just(resultUuid);
    }

    private static LimitViolation fromEntity(LimitViolationEntity entity) {
        return new LimitViolation(entity.getSubjectId(), entity.getLimitType(), entity.getLimitName(), entity.getAcceptableDuration(),
                entity.getLimit(), entity.getLimitReduction(), entity.getValue(), entity.getSide());
    }

    private static boolean fromEntity(ComputationStatusEntity entity) {
        return entity.isOk();
    }

    private static Contingency fromEntity(ContingencyEntity entity) {
        Stream<ContingencyElement> branchStream = entity.getBranchIds() != null
                ? entity.getBranchIds().stream().map(BranchContingency::new)
                : Stream.empty();
        Stream<ContingencyElement> generatorStream = entity.getGeneratorIds() != null
                ? entity.getGeneratorIds().stream().map(GeneratorContingency::new)
                : Stream.empty();
        return new Contingency(entity.getContingencyId(), Stream.concat(branchStream, generatorStream).collect(Collectors.toList()));
    }

    public Mono<SecurityAnalysisResult> getResult(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(limitTypes);

        Mono<Map<String, Boolean>> computationsStatusesMono = computationStatusRepository.findByResultUuid(resultUuid)
                .collectMap(ComputationStatusEntity::getContingencyId, SecurityAnalysisService::fromEntity);
        Mono<Map<String, Collection<LimitViolation>>> limitViolationsMono
                = (limitTypes.isEmpty() ? limitViolationRepository.findByResultUuid(resultUuid) : limitViolationRepository.findByResultUuidAndLimitTypeIn(resultUuid, limitTypes))
                .collectMultimap(LimitViolationEntity::getContingencyId, SecurityAnalysisService::fromEntity);
        Mono<List<Contingency>> contingenciesMono = contingencyRepository.findByResultUuid(resultUuid)
                .map(SecurityAnalysisService::fromEntity)
                .collectList();

        return Mono.zip(computationsStatusesMono, limitViolationsMono, contingenciesMono)
                .flatMap(tuple -> {
                    Map<String, Boolean> computationsStatuses = tuple.getT1();
                    Map<String, Collection<LimitViolation>> limitViolations = tuple.getT2();
                    List<Contingency> contingencies = tuple.getT3();

                    if (computationsStatuses.isEmpty()) {
                        return Mono.empty();
                    }

                    LimitViolationsResult preContingencyResult = new LimitViolationsResult(computationsStatuses.get(""),
                            new ArrayList<>(limitViolations.getOrDefault("", Collections.emptyList())));

                    List<PostContingencyResult> postContingencyResults = contingencies.stream()
                            .map(contingency -> new PostContingencyResult(contingency,
                                    computationsStatuses.get(contingency.getId()),
                                    new ArrayList<>(limitViolations.getOrDefault(contingency.getId(), Collections.emptyList()))))
                            .collect(Collectors.toList());

                    return Mono.just(new SecurityAnalysisResult(preContingencyResult, postContingencyResults));
                })
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }

    public Mono<Void> deleteResult(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        Mono<Void> v1 = computationStatusRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v2 = limitViolationRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v3 = contingencyRepository.deleteByResultUuid(resultUuid);
        return Flux.concat(v1, v2, v3)
                .then()
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }

    public Mono<Void> deleteResults() {
        Mono<Void> v1 = computationStatusRepository.deleteAll();
        Mono<Void> v2 = limitViolationRepository.deleteAll();
        Mono<Void> v3 = contingencyRepository.deleteAll();
        return Flux.concat(v1, v2, v3)
                .then()
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }
}
