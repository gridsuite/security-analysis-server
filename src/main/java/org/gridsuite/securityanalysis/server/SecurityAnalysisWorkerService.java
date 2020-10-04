/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.PowsyblException;
import com.powsybl.computation.local.LocalComputationManager;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.iidm.mergingview.MergingView;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.xml.NetworkXml;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

import java.io.UncheckedIOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisWorkerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisWorkerService.class);

    private static final String CATEGORY_BROKER_INPUT = SecurityAnalysisWorkerService.class.getName()
            + ".input-broker-messages";

    private NetworkStoreService networkStoreService;

    private ActionsService actionsService;

    private ComputationStatusRepository computationStatusRepository;

    private ContingencyRepository contingencyRepository;

    private LimitViolationRepository limitViolationRepository;

    private ObjectMapper objectMapper;

    private SecurityAnalysisConfigService config;

    private SecurityAnalysisResultPublisherService resultPublisher;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService,
                                         ComputationStatusRepository computationStatusRepository, ContingencyRepository contingencyRepository,
                                         LimitViolationRepository limitViolationRepository, ObjectMapper objectMapper,
                                         SecurityAnalysisConfigService config, SecurityAnalysisResultPublisherService resultPublisher) {
        this.networkStoreService = Objects.requireNonNull(networkStoreService);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.computationStatusRepository = Objects.requireNonNull(computationStatusRepository);
        this.contingencyRepository = Objects.requireNonNull(contingencyRepository);
        this.limitViolationRepository = Objects.requireNonNull(limitViolationRepository);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.config = Objects.requireNonNull(config);
        this.resultPublisher = Objects.requireNonNull(resultPublisher);
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

    private static List<String> splitHeader(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null || header.isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.asList(header.split(","));
    }

    private static String getHeader(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null) {
            throw new PowsyblException("Header '" + name + "' not found");
        }
        return header;
    }

    public Tuple2<UUID, SecurityAnalysisRunContext> parseMessage(Message<String> message) {
        MessageHeaders headers = message.getHeaders();
        UUID resultUuid = UUID.fromString(getHeader(headers, "resultUuid"));
        UUID networkUuid = UUID.fromString(getHeader(headers, "networkUuid"));
        List<UUID> otherNetworkUuids = splitHeader(headers, "otherNetworkUuids")
                .stream()
                .map(UUID::fromString)
                .collect(Collectors.toList());
        List<String> contingencyListNames = splitHeader(headers, "contingencyListNames");
        SecurityAnalysisParameters parameters;
        try {
            parameters = objectMapper.readValue(message.getPayload(), SecurityAnalysisParameters.class);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        SecurityAnalysisRunContext context = new SecurityAnalysisRunContext(networkUuid, otherNetworkUuids, contingencyListNames, parameters);
        return Tuples.of(resultUuid, context);
    }

    public Mono<SecurityAnalysisResult> run(SecurityAnalysisRunContext context) {
        Objects.requireNonNull(context);

        LOGGER.info("Run security analysis on contingency lists: {}", context.getContingencyListNames().stream().map(SecurityAnalysisWorkerService::sanitizeParam).collect(Collectors.toList()));

        Mono<Network> network = getNetwork(context.getNetworkUuid(), context.getOtherNetworkUuids())
                .map(NetworkXml::copy); // FIXME workaround for bus/breaker view impl not yet implemented in network store

        Mono<List<Contingency>> contingencies = Flux.fromIterable(context.getContingencyListNames())
                .flatMap(contingencyListName -> actionsService.getContingencyList(contingencyListName, context.getNetworkUuid()))
                .single();

        return Mono.zip(network, contingencies)
                .flatMap(tuple -> {
                    SecurityAnalysis securityAnalysis = config.getSecurityAnalysisFactory().create(tuple.getT1(), LocalComputationManager.getDefault(), 0);
                    CompletableFuture<SecurityAnalysisResult> result = securityAnalysis.run(VariantManagerConstants.INITIAL_VARIANT_ID, context.getParameters(), n -> tuple.getT2());
                    return Mono.fromCompletionStage(result);
                });
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

    private Mono<Void> save(UUID resultUuid, Contingency contingency, LimitViolationsResult limitViolationsResult) {
        return computationStatusRepository.insert(toEntity(resultUuid, contingency, limitViolationsResult.isComputationOk()))
                .flatMapMany(ignore -> limitViolationRepository.insert(toEntity(resultUuid, contingency, limitViolationsResult.getLimitViolations())))
                .then();
    }

    Mono<Void> save(SecurityAnalysisResult result, UUID resultUuid) {
        Objects.requireNonNull(result);
        Objects.requireNonNull(resultUuid);

        Mono<Void> preContingencyInsert = save(resultUuid, null, result.getPreContingencyResult());

        Mono<Void> postContingencyInsert = Flux.fromIterable(result.getPostContingencyResults())
                .flatMap(postContingencyResult -> save(resultUuid, postContingencyResult.getContingency(), postContingencyResult.getLimitViolationsResult())
                        .then(contingencyRepository.insert(toEntity(resultUuid, postContingencyResult.getContingency()))))
                .then();

        return preContingencyInsert
                .then(postContingencyInsert);
    }

    @Bean
    public Consumer<Flux<Message<String>>> consumeRun() {
        return f -> f.log(CATEGORY_BROKER_INPUT, Level.FINE)
                .flatMap(message -> {
                    Tuple2<UUID, SecurityAnalysisRunContext> tuple = parseMessage(message);
                    UUID resultUuid = tuple.getT1();
                    SecurityAnalysisRunContext context = tuple.getT2();
                    return run(context)
                            .flatMap(result -> save(result, resultUuid))
                            .doOnSuccess(unused -> resultPublisher.publish(resultUuid));
                })
                .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable))
                .subscribe();
    }
}
