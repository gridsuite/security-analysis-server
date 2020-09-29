/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.commons.PowsyblException;
import com.powsybl.computation.local.LocalComputationManager;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.contingency.GeneratorContingency;
import com.powsybl.iidm.mergingview.MergingView;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.xml.NetworkXml;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Mono;

import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@ComponentScan(basePackageClasses = {NetworkStoreService.class})
@Service
public class SecurityAnalysisService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisService.class);

    private NetworkStoreService networkStoreService;

    private ActionsService actionsService;

    private ComputationStatusRepository computationStatusRepository;

    private ContingencyRepository contingencyRepository;

    private LimitViolationRepository limitViolationRepository;

    @Value("${securityAnalysisFactoryClass}")
    private String securityAnalysisFactoryClass;

    public SecurityAnalysisService(NetworkStoreService networkStoreService, ActionsService actionsService,
                                   ComputationStatusRepository computationStatusRepository, ContingencyRepository contingencyRepository,
                                   LimitViolationRepository limitViolationRepository) {
        this.networkStoreService = Objects.requireNonNull(networkStoreService);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.computationStatusRepository = Objects.requireNonNull(computationStatusRepository);
        this.contingencyRepository = Objects.requireNonNull(contingencyRepository);
        this.limitViolationRepository = Objects.requireNonNull(limitViolationRepository);
    }

    private SecurityAnalysisFactory getSecurityAnalysisFactory() {
        try {
            return (SecurityAnalysisFactory) Class.forName(securityAnalysisFactoryClass).getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | InvocationTargetException e) {
            throw new PowsyblException(e);
        }
    }

    private static String sanitizeParam(String param) {
        return param != null ? param.replaceAll("[\n|\r|\t]", "_") : null;
    }

    private Mono<Network> getNetwork(UUID networkUuid) {
        // FIXME to re-implement when network store service will be reactive
        return Mono.fromCallable(() -> {
            try {
                return networkStoreService.getNetwork(networkUuid, PreloadingStrategy.COLLECTION);
            } catch (PowsyblException e) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Network '" + networkUuid + "' not found");
            }
        });
    }

    private Mono<Network> getNetwork(UUID networkUuid, List<UUID> otherNetworkUuids) {
        Mono<Network> network = getNetwork(networkUuid);
        if (otherNetworkUuids.isEmpty()) {
            return network;
        } else {
            Mono<List<Network>> otherNetworks = Flux.fromIterable(otherNetworkUuids)
                    .flatMap(this::getNetwork)
                    .collectList();
            return Mono.zip(network, otherNetworks)
                    .map(t -> {
                        // creation of the merging view
                        List<Network> networks = new ArrayList<>();
                        networks.add(t.getT1());
                        networks.addAll(t.getT2());
                        MergingView mergingView = MergingView.create("merge", "iidm");
                        mergingView.merge(networks.toArray(new Network[0]));
                        return mergingView;
                    });
        }
    }

    public Mono<SecurityAnalysisResult> run(UUID networkUuid, List<UUID> otherNetworksUuid, List<String> contingencyListNames,
                                            SecurityAnalysisParameters parameters) {
        Objects.requireNonNull(networkUuid);
        Objects.requireNonNull(otherNetworksUuid);
        Objects.requireNonNull(contingencyListNames);
        Objects.requireNonNull(parameters);

        LOGGER.info("Run security analysis on contingency lists: {}", contingencyListNames.stream().map(SecurityAnalysisService::sanitizeParam).collect(Collectors.toList()));

        Mono<Network> network = getNetwork(networkUuid, otherNetworksUuid)
                .map(NetworkXml::copy); // FIXME workaround for bus/breaker view impl not yet implemented in network store

        Mono<List<Contingency>> contingencies = Flux.fromIterable(contingencyListNames)
                .flatMap(contingencyListName -> actionsService.getContingencyList(contingencyListName, networkUuid))
                .single();

        return Mono.zip(network, contingencies)
                .flatMap(tuple -> {
                    SecurityAnalysis securityAnalysis = getSecurityAnalysisFactory().create(tuple.getT1(), LocalComputationManager.getDefault(), 0);
                    CompletableFuture<SecurityAnalysisResult> result = securityAnalysis.run(VariantManagerConstants.INITIAL_VARIANT_ID, parameters, n -> tuple.getT2());
                    return Mono.fromCompletionStage(result);
                });
    }

    private static LimitViolationEntity toEntity(UUID resultUuid, String contingencyId, LimitViolation limitViolation) {
        return new LimitViolationEntity(resultUuid, limitViolation.getLimitType(), contingencyId, limitViolation.getSubjectId(),
                limitViolation.getSubjectName(), limitViolation.getLimit(), limitViolation.getLimitName(),
                limitViolation.getAcceptableDuration(), limitViolation.getLimitReduction(), limitViolation.getValue(),
                limitViolation.getSide());
    }

    private static LimitViolation fromEntity(LimitViolationEntity entity) {
        return new LimitViolation(entity.getSubjectId(), entity.getLimitType(), entity.getLimitName(), entity.getAcceptableDuration(),
                entity.getLimit(), entity.getLimitReduction(), entity.getValue(), entity.getSide());
    }

    private static ComputationStatusEntity toEntity(UUID resultUuid, Contingency contingency, boolean ok) {
        return new ComputationStatusEntity(resultUuid, contingency != null ? contingency.getId() : "", ok);
    }

    private static boolean fromEntity(ComputationStatusEntity entity) {
        return entity.isOk();
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

    private static Contingency fromEntity(ContingencyEntity entity) {
        Stream<ContingencyElement> branchStream = entity.getBranchIds() != null
                ? entity.getBranchIds().stream().map(BranchContingency::new)
                : Stream.empty();
        Stream<ContingencyElement> generatorStream = entity.getGeneratorIds() != null
                ? entity.getGeneratorIds().stream().map(GeneratorContingency::new)
                : Stream.empty();
        return new Contingency(entity.getContingencyId(), Stream.concat(branchStream, generatorStream).collect(Collectors.toList()));
    }

    private Mono<Void> save(UUID resultUuid, Contingency contingency, LimitViolationsResult limitViolationsResult) {
        return computationStatusRepository.insert(toEntity(resultUuid, contingency, limitViolationsResult.isComputationOk()))
                .flatMapMany(ignore -> limitViolationRepository.insert(toEntity(resultUuid, contingency, limitViolationsResult.getLimitViolations())))
                .then();
    }

    UUID generateResultUuid() {
        return UUID.randomUUID();
    }

    private Mono<UUID> save(SecurityAnalysisResult result) {
        Objects.requireNonNull(result);
        Hooks.onOperatorDebug();

        UUID resultUuid = generateResultUuid();

        Mono<Void> preContingencyInsert = save(resultUuid, null, result.getPreContingencyResult());

        Mono<Void> postContingencyInsert = Flux.fromIterable(result.getPostContingencyResults())
                .flatMap(postContingencyResult -> save(resultUuid, postContingencyResult.getContingency(), postContingencyResult.getLimitViolationsResult())
                        .then(contingencyRepository.insert(toEntity(resultUuid, postContingencyResult.getContingency()))))
                .then();

        return preContingencyInsert
                .then(postContingencyInsert)
                .thenReturn(resultUuid);
    }

    public Mono<UUID> runAndSave(UUID networkUuid, List<UUID> otherNetworksUuid, List<String> contingencyListNames,
                                 SecurityAnalysisParameters parameters) {
        return run(networkUuid, otherNetworksUuid, contingencyListNames, parameters)
                .flatMap(this::save);
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
                });
    }

    public Mono<Void> deleteResult(UUID resultUuid) {
        Objects.requireNonNull(resultUuid);
        Mono<Void> v1 = computationStatusRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v2 = limitViolationRepository.deleteByResultUuid(resultUuid);
        Mono<Void> v3 = contingencyRepository.deleteByResultUuid(resultUuid);
        return Flux.concat(v1, v2, v3).then();
    }
}
