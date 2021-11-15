/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import com.powsybl.commons.PowsyblException;
import com.powsybl.computation.local.LocalComputationManager;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.mergingview.MergingView;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.LimitViolationFilter;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisReport;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.repository.SecurityAnalysisResultRepository;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisStoppedPublisherService.CANCEL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisStoppedPublisherService.FAIL_MESSAGE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisWorkerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisWorkerService.class);

    private static final String CATEGORY_BROKER_OUTPUT = SecurityAnalysisWorkerService.class.getName() + ".output-broker-messages";

    private static final Logger OUTPUT_MESSAGE_LOGGER = LoggerFactory.getLogger(CATEGORY_BROKER_OUTPUT);

    private NetworkStoreService networkStoreService;

    private ActionsService actionsService;

    private SecurityAnalysisResultRepository resultRepository;

    private ObjectMapper objectMapper;

    private SecurityAnalysisStoppedPublisherService stoppedPublisherService;

    private Map<UUID, CompletableFuture<SecurityAnalysisResult>> futures = new ConcurrentHashMap<>();

    private Map<UUID, SecurityAnalysisCancelContext> cancelComputationRequests = new ConcurrentHashMap<>();

    private Set<UUID> runRequests = Sets.newConcurrentHashSet();

    @Autowired
    private StreamBridge resultMessagePublisher;

    private Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier = SecurityAnalysisUtil::getRunner;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService,
                                         SecurityAnalysisResultRepository resultRepository, ObjectMapper objectMapper,
                                         SecurityAnalysisStoppedPublisherService stoppedPublisherService) {
        this.networkStoreService = Objects.requireNonNull(networkStoreService);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.resultRepository = Objects.requireNonNull(resultRepository);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.stoppedPublisherService = Objects.requireNonNull(stoppedPublisherService);
    }

    public void setSecurityAnalysisFactorySupplier(Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier) {
        this.securityAnalysisFactorySupplier = Objects.requireNonNull(securityAnalysisFactorySupplier);
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
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
            }
        })
                .subscribeOn(Schedulers.boundedElastic());
    }

    private Mono<Network> getNetwork(UUID networkUuid, List<UUID> otherNetworkUuids) {
        Mono<Network> network = getNetwork(networkUuid);
        if (otherNetworkUuids.isEmpty()) {
            return network;
        } else {
            Mono<List<Network>> otherNetworks = Flux.fromIterable(otherNetworkUuids)
                    .flatMap(uuid -> getNetwork(uuid))
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

    public Mono<SecurityAnalysisResult> run(SecurityAnalysisRunContext context) {
        return run(context, null);
    }

    private Mono<SecurityAnalysisResult> run(SecurityAnalysisRunContext context, UUID resultUuid) {
        Objects.requireNonNull(context);

        LOGGER.info("Run security analysis on contingency lists: {}", context.getContingencyListNames().stream().map(SecurityAnalysisWorkerService::sanitizeParam).collect(Collectors.toList()));

        Mono<Network> network = getNetwork(context.getNetworkUuid(), context.getOtherNetworkUuids());

        Mono<List<Contingency>> contingencies = Flux.fromIterable(context.getContingencyListNames())
                .flatMap(contingencyListName -> actionsService.getContingencyList(contingencyListName, context.getNetworkUuid(), context.getVariantId()))
                .collectList();

        String variantId = context.getVariantId() != null ? context.getVariantId() : VariantManagerConstants.INITIAL_VARIANT_ID;

        return Mono.zip(network, contingencies)
                .flatMap(tuple -> {
                    SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(context.getProvider());
                    CompletableFuture<SecurityAnalysisResult> future = securityAnalysisRunner.runAsync(
                        tuple.getT1(), variantId, new DefaultLimitViolationDetector(),
                        LimitViolationFilter.load(), LocalComputationManager.getDefault(),
                        context.getParameters(), n -> tuple.getT2(), Collections.emptyList(), Collections.emptyList()
                    ).thenApply(SecurityAnalysisReport::getResult);
                    if (resultUuid != null) {
                        futures.put(resultUuid, future);
                    }
                    if (resultUuid != null && cancelComputationRequests.get(resultUuid) != null) {
                        return Mono.empty();
                    } else {
                        return Mono.fromCompletionStage(future);
                    }
                });
    }

    @Bean
    public Consumer<Message<String>> consumeRun() {
        return message -> {
            SecurityAnalysisResultContext resultContext = SecurityAnalysisResultContext.fromMessage(message, objectMapper);
            runRequests.add(resultContext.getResultUuid());

            run(resultContext.getRunContext(), resultContext.getResultUuid())
                    .flatMap(result -> resultRepository.insert(resultContext.getResultUuid(), result)
                            .then(resultRepository.insertStatus(resultContext.getResultUuid(), SecurityAnalysisStatus.COMPLETED.name()))
                            .then(Mono.just(result)))
                    .doOnSuccess(result -> {
                        if (result != null) {  // result available
                            Message<String> sendMessage = MessageBuilder
                                    .withPayload("")
                                    .setHeader("resultUuid", resultContext.getResultUuid().toString())
                                    .setHeader("receiver", resultContext.getRunContext().getReceiver())
                                    .build();
                            sendResultMessage(sendMessage);
                            LOGGER.info("Security analysis complete (resultUuid='{}')", resultContext.getResultUuid());
                        } else {  // result not available : stop computation request
                            if (cancelComputationRequests.get(resultContext.getResultUuid()) != null) {
                                stoppedPublisherService.publishCancel(resultContext.getResultUuid(), cancelComputationRequests.get(resultContext.getResultUuid()).getReceiver());
                            }
                        }
                    })
                    .onErrorResume(throwable -> {
                        if (!(throwable instanceof CancellationException)) {
                            LOGGER.error(FAIL_MESSAGE, throwable);
                            stoppedPublisherService.publishFail(resultContext.getResultUuid(), resultContext.getRunContext().getReceiver(), throwable.getMessage());
                            return resultRepository.delete(resultContext.getResultUuid()).then(Mono.empty());
                        }
                        return Mono.empty();
                    })
                    .doFinally(s -> {
                        futures.remove(resultContext.getResultUuid());
                        cancelComputationRequests.remove(resultContext.getResultUuid());
                        runRequests.remove(resultContext.getResultUuid());
                    })
                    .subscribe();
        };
    }

    @Bean
    public Consumer<Message<String>> consumeCancel() {
        return message -> {
            SecurityAnalysisCancelContext cancelContext = SecurityAnalysisCancelContext.fromMessage(message);

            if (runRequests.contains(cancelContext.getResultUuid())) {
                cancelComputationRequests.put(cancelContext.getResultUuid(), cancelContext);
            }

            // find the completableFuture associated with result uuid
            CompletableFuture<SecurityAnalysisResult> future = futures.get(cancelContext.getResultUuid());
            if (future != null) {
                future.cancel(true);  // cancel computation in progress

                resultRepository.delete(cancelContext.getResultUuid())
                        .doOnSuccess(unused -> {
                            stoppedPublisherService.publishCancel(cancelContext.getResultUuid(), cancelContext.getReceiver());
                            LOGGER.info(CANCEL_MESSAGE + " (resultUuid='{}')", cancelContext.getResultUuid());
                        })
                        .doOnError(throwable -> LOGGER.error(throwable.toString(), throwable))
                        .subscribe();
            }
        };
    }

    private void sendResultMessage(Message<String> message) {
        OUTPUT_MESSAGE_LOGGER.debug("Sending message : {}", message);
        resultMessagePublisher.send("publishResult-out-0", message);
    }
}
