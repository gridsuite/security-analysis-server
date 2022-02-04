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

import org.hibernate.Hibernate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

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

    @Lazy
    @Autowired
    private SecurityAnalysisResultRepository self;

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
        Mono<Map<String, Boolean>> computationsStatusesMono;
        List<ComputationStatusEntity> statusEntities = computationStatusRepository.findByResultUuid(resultUuid);
        Hibernate.initialize(statusEntities);

        computationsStatusesMono = Flux.fromIterable(statusEntities)
                .collectMap(ComputationStatusEntity::getContingencyId, SecurityAnalysisResultRepository::fromEntity);
        Mono<Map<String, Collection<LimitViolation>>> limitViolationsMono;
        List<LimitViolationEntity> limitViolationEntities = limitTypes.isEmpty()
            ? limitViolationRepository.findByResultUuid(resultUuid)
            : limitViolationRepository.findByResultUuidAndLimitTypeIn(resultUuid, limitTypes);
        Hibernate.initialize(limitViolationEntities);

        limitViolationsMono = Flux.fromIterable(limitViolationEntities)
            .collectMultimap(LimitViolationEntity::getContingencyId, SecurityAnalysisResultRepository::fromEntity);
        List<ContingencyEntity> contingencyEntities = contingencyRepository.findByResultUuid(resultUuid);
        Hibernate.initialize(contingencyEntities);
        contingencyEntities.forEach(entity -> {
            Hibernate.initialize(entity.getBranchIds());
            Hibernate.initialize(entity.getGeneratorIds());
        });

        Mono<List<Contingency>> contingenciesMono = Flux.fromIterable(contingencyEntities)
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

                    List<PostContingencyResult> postContingencyResults = contingencies.stream()//.filter(Objects::nonNull)
                            .map(contingency -> {
                                Boolean computationOk = computationsStatuses.get(contingency.getId());
                                ArrayList<LimitViolation> limitViolations1 = new ArrayList<>(
                                    limitViolations.getOrDefault(contingency.getId(), Collections.emptyList()));
                                return new PostContingencyResult(contingency, computationOk != null && computationOk,
                                    limitViolations1);
                            })
                            .collect(Collectors.toList());

                    return Mono.just(new SecurityAnalysisResult(preContingencyResult, postContingencyResults));
                });
    }

    @Transactional(readOnly = true)
    public Mono<SecurityAnalysisResult> find(UUID resultUuid, Set<LimitViolationType> limitTypes) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(limitTypes);

        // !!! we can just check if result is available by looking at pre computation status because it is written last
        // see insert method comment, so this mono is empty if result has not been found or not fully written
        return Flux.fromIterable(computationStatusRepository.findByResultUuidAndContingencyId(resultUuid, ""))
                .then(createResultMono(resultUuid, limitTypes))
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable));
    }

    private Mono<Void> save(UUID resultUuid, Contingency contingency, LimitViolationsResult limitViolationsResult) {
        return Mono.fromCallable(
            () -> {
                ComputationStatusEntity entity = toEntity(resultUuid, contingency, limitViolationsResult.isComputationOk());
                ComputationStatusEntity saved = computationStatusRepository.save(entity);
                return saved;
            })
            .flatMapMany(ignore -> Mono.fromCallable(()
                -> limitViolationRepository.saveAll(toEntity(resultUuid, contingency, limitViolationsResult.getLimitViolations())))
            ).then();
    }

    //@Transactional
    public Mono<Void> insert(UUID resultUuid, SecurityAnalysisResult result) {
        Objects.requireNonNull(resultUuid);
        Objects.requireNonNull(result);

        Mono<Void> preContingencyInsert = save(resultUuid, null, result.getPreContingencyResult().getLimitViolationsResult());

        Mono<Void> postContingencyInsert = Flux.fromIterable(result.getPostContingencyResults())
            .flatMap(postContingencyResult
                -> save(resultUuid, postContingencyResult.getContingency(), postContingencyResult.getLimitViolationsResult())
                .then(Mono.fromCallable(
                    () -> contingencyRepository.save(toEntity(resultUuid, postContingencyResult.getContingency())))))
            .then();

        // !!! save pre-contingency result last so we can rely on it to known if full result is available
        return postContingencyInsert
                .then(preContingencyInsert);
    }

    public Mono<Void> delete(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return Mono.fromRunnable(() -> {
            self.doDelete(resultUuid);
        }).doOnError(throwable -> LOGGER.error(throwable.toString(), throwable)).then();
    }

    @Transactional
    public void doDelete(UUID resultUuid) {
        computationStatusRepository.deleteByResultUuid(resultUuid);
        limitViolationRepository.deleteByResultUuid(resultUuid);
        contingencyRepository.deleteByResultUuid(resultUuid);
        globalStatusRepository.deleteByResultUuid(resultUuid);
    }

    public Mono<Void> deleteAll() {
        return Mono.fromRunnable(() -> {
            self.doDeleteAll();
        }).doOnError(throwable -> LOGGER.error(throwable.toString(), throwable)).then();
    }

    @Transactional
    public void doDeleteAll() {
        computationStatusRepository.deleteAll();
        limitViolationRepository.deleteAll();
        contingencyRepository.deleteAll();
        globalStatusRepository.deleteAll();
    }

    public Mono<String> findStatus(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        return Mono.fromCallable(() -> self.doFindStatus(resultUuid));
    }

    @Transactional(readOnly = true)
    public String doFindStatus(UUID resultUuid) {
        GlobalStatusEntity byResultUuid = globalStatusRepository.findByResultUuid(resultUuid);
        return byResultUuid == null ? null : byResultUuid.getStatus();
    }

    private static GlobalStatusEntity toEntity(UUID resultUuid, String status) {
        return new GlobalStatusEntity(resultUuid, status);
    }

    public Mono<Void> insertStatus(List<UUID> resultUuids, String status) {
        Objects.requireNonNull(resultUuids);
        return Mono.fromRunnable(() -> self.doInsertStatus(resultUuids, status)).then();
    }

    @Transactional
    public List<GlobalStatusEntity> doInsertStatus(List<UUID> resultUuids, String status) {
        return globalStatusRepository.saveAll(resultUuids.stream()
            .map(uuid -> toEntity(uuid, status)).collect(Collectors.toList()));
    }

}
