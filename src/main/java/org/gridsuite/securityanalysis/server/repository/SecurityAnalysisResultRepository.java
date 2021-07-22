/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repository;

import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.contingency.GeneratorContingency;
import com.powsybl.security.*;
import com.powsybl.security.results.PostContingencyResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Repository
public class SecurityAnalysisResultRepository {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisResultRepository.class);

    private ComputationStatusRepository computationStatusRepository;

    private ContingencyRepository contingencyRepository;

    private LimitViolationRepository limitViolationRepository;

    private GlobalStatusRepository globalStatusRepository;

    public SecurityAnalysisResultRepository(ComputationStatusRepository computationStatusRepository,
                                            ContingencyRepository contingencyRepository,
                                            LimitViolationRepository limitViolationRepository,
                                            GlobalStatusRepository globalStatusRepository) {
        this.computationStatusRepository = computationStatusRepository;
        this.contingencyRepository = contingencyRepository;
        this.limitViolationRepository = limitViolationRepository;
        this.globalStatusRepository = globalStatusRepository;
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

    private static LimitViolationEntity toEntity(UUID resultUuid, String contingencyId, LimitViolation limitViolation) {
        return new LimitViolationEntity(resultUuid, limitViolation.getLimitType(), contingencyId, limitViolation.getSubjectId(),
                limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
                limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
                limitViolation.getSide());
    }

    private static ComputationStatusEntity toEntity(UUID resultUuid, Contingency contingency, boolean ok) {
        return new ComputationStatusEntity(resultUuid, contingency != null ? contingency.getId() : "", ok);
    }

    private static List<LimitViolationEntity> toEntity(UUID resultUuid, Contingency contingency, List<LimitViolation> limitViolations) {
        return limitViolations
                .stream()
                .map(limitViolation -> toEntity(resultUuid, contingency != null ? contingency.getId() : "", limitViolation))
                .collect(Collectors.toList());
    }

    private static ContingencyEntity toEntity(UUID resultUuid, Contingency contingency) {
        List<String> branchIds = new ArrayList<>();
        List<String> generatorIds = new ArrayList<>();
        for (ContingencyElement element : contingency.getElements()) {
            switch (element.getType()) {
                case LINE:
                case BRANCH:
                    branchIds.add(element.getId());
                    break;
                case GENERATOR:
                    generatorIds.add(element.getId());
                    break;
                default:
                    throw new IllegalStateException("Element type yet support: " + element.getType());
            }
        }
        return new ContingencyEntity(resultUuid, contingency.getId(), branchIds, generatorIds);
    }

    private Mono<SecurityAnalysisResult> createResultMono(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        // load all rows related to this result UUID
        Mono<Map<String, Boolean>> computationsStatusesMono = computationStatusRepository.findByResultUuid(resultUuid)
                .collectMap(ComputationStatusEntity::getContingencyId, SecurityAnalysisResultRepository::fromEntity);
        Mono<Map<String, Collection<LimitViolation>>> limitViolationsMono
                = (limitTypes.isEmpty() ? limitViolationRepository.findByResultUuid(resultUuid) : limitViolationRepository.findByResultUuidAndLimitTypeIn(resultUuid, limitTypes))
                .collectMultimap(LimitViolationEntity::getContingencyId, SecurityAnalysisResultRepository::fromEntity);
        Mono<List<Contingency>> contingenciesMono = contingencyRepository.findByResultUuid(resultUuid)
                .map(SecurityAnalysisResultRepository::fromEntity)
                .collectList();

        // and then rebuild security analysis data structure
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
                });
    }

    public Mono<SecurityAnalysisResult> find(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(limitTypes);

        // !!! we can just check if result is available by looking at pre computation status because it is written last
        // see insert method comment, so this mono is empty if result has not been found or not fully written
        return computationStatusRepository.findByResultUuidAndContingencyId(resultUuid, "")
                .then(createResultMono(resultUuid, limitTypes))
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }

    private Mono<Void> save(UUID resultUuid, Contingency contingency, LimitViolationsResult limitViolationsResult) {
        return computationStatusRepository.insert(toEntity(resultUuid, contingency, limitViolationsResult.isComputationOk()))
                .flatMapMany(ignore -> limitViolationRepository.insert(toEntity(resultUuid, contingency, limitViolationsResult.getLimitViolations())))
                .then();
    }

    public Mono<Void> insert(UUID resultUuid, SecurityAnalysisResult result) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(result);

        Mono<Void> preContingencyInsert = save(resultUuid, null, result.getPreContingencyResult().getLimitViolationsResult());

        Mono<Void> postContingencyInsert = Flux.fromIterable(result.getPostContingencyResults())
                .flatMap(postContingencyResult -> save(resultUuid, postContingencyResult.getContingency(), postContingencyResult.getLimitViolationsResult())
                        .then(contingencyRepository.insert(toEntity(resultUuid, postContingencyResult.getContingency()))))
                .then();

        // !!! save pre-contingency result last so we can rely on it to known if full result is available
        return postContingencyInsert
                .then(preContingencyInsert);
    }

    public Mono<Void> delete(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        Mono<Void> v1 = computationStatusRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v2 = limitViolationRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v3 = contingencyRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v4 = globalStatusRepository.deleteByResultUuid(resultUuid);
        return Flux.concat(v1, v2, v3, v4)
                .then()
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }

    public Mono<Void> deleteAll() {
        Mono<Void> v1 = computationStatusRepository.deleteAll();
        Mono<Void> v2 = limitViolationRepository.deleteAll();
        Mono<Void> v3 = contingencyRepository.deleteAll();
        Mono<Void> v4 = globalStatusRepository.deleteAll();
        return Flux.concat(v1, v2, v3, v4)
                .then()
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }

    public Mono<String> findStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return globalStatusRepository.findByResultUuid(resultUuid).map(GlobalStatusEntity::getStatus);
    }

    private static GlobalStatusEntity toEntity(UUID resultUuid, String status) {
        return new GlobalStatusEntity(resultUuid, status);
    }

    public Mono<Void> insertStatus(UUID resultUuid, String status) {
        Objects.requireNonNull(resultUuid);
        return globalStatusRepository.insert(toEntity(resultUuid, status))
                .then();
    }
}
