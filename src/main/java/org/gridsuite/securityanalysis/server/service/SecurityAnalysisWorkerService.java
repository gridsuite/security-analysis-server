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
import com.powsybl.commons.reporter.Reporter;
import com.powsybl.commons.reporter.ReporterModel;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.mergingview.MergingView;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.LimitViolationFilter;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisReport;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.ws.commons.LogUtils;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.function.Tuple2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.gridsuite.securityanalysis.server.service.NotificationService.CANCEL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.NotificationService.FAIL_MESSAGE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisWorkerService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisWorkerService.class);

    private static final String AS_TYPE_REPORT = "SecurityAnalysis";

    private NetworkStoreService networkStoreService;

    private ActionsService actionsService;

    private ReportService reportService;

    private NotificationService notificationService;

    private SecurityAnalysisResultRepository resultRepository;

    private ObjectMapper objectMapper;

    private Map<UUID, CompletableFuture<SecurityAnalysisResult>> futures = new ConcurrentHashMap<>();

    private Map<UUID, SecurityAnalysisCancelContext> cancelComputationRequests = new ConcurrentHashMap<>();

    private Set<UUID> runRequests = Sets.newConcurrentHashSet();

    private Lock lockRunAndCancelAS = new ReentrantLock();

    private Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier;

    private SecurityAnalysisExecutionService securityAnalysisExecutionService;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService, ReportService reportService,
                                         SecurityAnalysisResultRepository resultRepository, ObjectMapper objectMapper,
                                         SecurityAnalysisRunnerSupplier securityAnalysisRunnerSupplier, NotificationService notificationService, SecurityAnalysisExecutionService securityAnalysisExecutionService) {
        this.networkStoreService = Objects.requireNonNull(networkStoreService);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.reportService = Objects.requireNonNull(reportService);
        this.resultRepository = Objects.requireNonNull(resultRepository);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.notificationService = Objects.requireNonNull(notificationService);
        this.securityAnalysisExecutionService = Objects.requireNonNull(securityAnalysisExecutionService);
        this.securityAnalysisFactorySupplier = securityAnalysisRunnerSupplier::getRunner;
    }

    public void setSecurityAnalysisFactorySupplier(Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier) {
        this.securityAnalysisFactorySupplier = Objects.requireNonNull(securityAnalysisFactorySupplier);
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

    public Mono<SecurityAnalysisResult> run(SecurityAnalysisRunContext context) {
        return run(context, null);
    }

    private CompletableFuture<SecurityAnalysisResult> runASAsync(SecurityAnalysisRunContext context,
                                                                 SecurityAnalysis.Runner securityAnalysisRunner,
                                                                 Tuple2<Network, List<Contingency>> tuple,
                                                                 Reporter reporter,
                                                                 UUID resultUuid) {
        lockRunAndCancelAS.lock();
        try {
            if (resultUuid != null && cancelComputationRequests.get(resultUuid) != null) {
                return null;
            }
            String variantId = context.getVariantId() != null ? context.getVariantId() : VariantManagerConstants.INITIAL_VARIANT_ID;

            CompletableFuture<SecurityAnalysisResult> future = securityAnalysisRunner.runAsync(
                tuple.getT1(),
                variantId,
                n -> tuple.getT2(),
                context.getParameters(),
                securityAnalysisExecutionService.getLocalComputationManager(),
                LimitViolationFilter.load(),
                new DefaultLimitViolationDetector(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                reporter)
                .thenApply(SecurityAnalysisReport::getResult);
            if (resultUuid != null) {
                futures.put(resultUuid, future);
            }
            return future;
        } finally {
            lockRunAndCancelAS.unlock();
        }
    }

    private void cancelASAsync(SecurityAnalysisCancelContext cancelContext) {
        lockRunAndCancelAS.lock();
        try {
            cancelComputationRequests.put(cancelContext.getResultUuid(), cancelContext);

            // find the completableFuture associated with result uuid
            CompletableFuture<SecurityAnalysisResult> future = futures.get(cancelContext.getResultUuid());
            if (future != null) {
                future.cancel(true);  // cancel computation in progress

                cleanASResultsAndPublishCancel(cancelContext.getResultUuid(), cancelContext.getReceiver());
            }
        } finally {
            lockRunAndCancelAS.unlock();
        }
    }

    private void cleanASResultsAndPublishCancel(UUID resultUuid, String receiver) {
        resultRepository.delete(resultUuid);
        notificationService.emitStopAnalysisMessage(resultUuid.toString(), receiver);
        LOGGER.info(CANCEL_MESSAGE + " (resultUuid='{}')", resultUuid);
    }

    private Mono<SecurityAnalysisResult> run(SecurityAnalysisRunContext context, UUID resultUuid) {
        Objects.requireNonNull(context);

        LOGGER.info("Run security analysis on contingency lists: {}", context.getContingencyListNames().stream().map(LogUtils::sanitizeParam).collect(Collectors.toList()));

        Mono<Network> network = getNetwork(context.getNetworkUuid(), context.getOtherNetworkUuids());

        Mono<List<Contingency>> contingencies = Flux.fromIterable(context.getContingencyListNames())
                .flatMap(contingencyListName -> actionsService.getContingencyList(contingencyListName, context.getNetworkUuid(), context.getVariantId()))
                .collectList();

        return Mono.zip(network, contingencies)
                .flatMap(tuple -> {

                    SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(context.getProvider());

                    Reporter rootReporter = Reporter.NO_OP;
                    Reporter reporter = Reporter.NO_OP;
                    if (context.getReportUuid() != null) {
                        String rootReporterId = context.getReporterId() == null ? AS_TYPE_REPORT : context.getReporterId() + "@" + AS_TYPE_REPORT;
                        rootReporter = new ReporterModel(rootReporterId, rootReporterId);
                        reporter = rootReporter.createSubReporter(AS_TYPE_REPORT, AS_TYPE_REPORT + " (${providerToUse})", "providerToUse", securityAnalysisRunner.getName());
                    }

                    CompletableFuture<SecurityAnalysisResult> future = runASAsync(context, securityAnalysisRunner, tuple, reporter, resultUuid);

                    Mono<SecurityAnalysisResult> result = future == null ? Mono.empty() : Mono.fromCompletionStage(future);
                    if (context.getReportUuid() != null) {
                        Reporter finalRootReporter = rootReporter;
                        return result.zipWhen(r -> reportService.sendReport(context.getReportUuid(), finalRootReporter)
                                .thenReturn("") /* because zipWhen needs 2 non empty mono */)
                        .map(Tuple2::getT1);
                    } else {
                        return result;
                    }
                });
    }

    @Bean
    public Consumer<Message<String>> consumeRun() {
        return message -> {
            try {
                SecurityAnalysisResultContext resultContext = SecurityAnalysisResultContext.fromMessage(message, objectMapper);
                runRequests.add(resultContext.getResultUuid());
                AtomicReference<Long> startTime = new AtomicReference<>();

                run(resultContext.getRunContext(), resultContext.getResultUuid())
                        .doOnSubscribe(x -> startTime.set(System.nanoTime()))
                        .flatMap(result -> {
                            long nanoTime = System.nanoTime();
                            LOGGER.info("Just run in {}s", TimeUnit.NANOSECONDS.toSeconds(nanoTime - startTime.getAndSet(nanoTime)));
                            return Mono.fromRunnable(() -> resultRepository.insert(resultContext.getResultUuid(), result))
                                    .then(Mono.fromRunnable(() -> resultRepository.insertStatus(List.of(resultContext.getResultUuid()),
                                            result.getPreContingencyLimitViolationsResult().isComputationOk() ? SecurityAnalysisStatus.CONVERGED.name() : SecurityAnalysisStatus.DIVERGED.name())))
                                    .then(Mono.just(result))
                                    .doFinally(ignored -> {
                                        long finalNanoTime = System.nanoTime();
                                        LOGGER.info("Stored in {}s", TimeUnit.NANOSECONDS.toSeconds(finalNanoTime - startTime.getAndSet(finalNanoTime)));
                                    });
                        })
                        .doOnSuccess(result -> {
                            if (result != null) {  // result available
                                notificationService.emitAnalysisResultsMessage(resultContext.getResultUuid().toString(), resultContext.getRunContext().getReceiver());
                                LOGGER.info("Security analysis complete (resultUuid='{}')", resultContext.getResultUuid());
                            } else {  // result not available : stop computation request
                                if (cancelComputationRequests.get(resultContext.getResultUuid()) != null) {
                                    cleanASResultsAndPublishCancel(resultContext.getResultUuid(), cancelComputationRequests.get(resultContext.getResultUuid()).getReceiver());
                                }
                            }
                        })
                        .onErrorResume(throwable -> {
                            if (!(throwable instanceof CancellationException)) {
                                LOGGER.error(FAIL_MESSAGE, throwable);
                                notificationService.emitFailAnalysisMessage(resultContext.getResultUuid().toString(),
                                        resultContext.getRunContext().getReceiver(),
                                        throwable.getMessage());
                                resultRepository.delete(resultContext.getResultUuid());
                                return Mono.empty();
                            }
                            return Mono.empty();
                        })
                        .doFinally(s -> {
                            futures.remove(resultContext.getResultUuid());
                            cancelComputationRequests.remove(resultContext.getResultUuid());
                            runRequests.remove(resultContext.getResultUuid());
                        })
                        .block();
            } catch (Exception e) {
                LOGGER.error("Exception in consumeRun", e);
            }
        };
    }

    @Bean
    public Consumer<Message<String>> consumeCancel() {
        return message -> cancelASAsync(SecurityAnalysisCancelContext.fromMessage(message));
    }
}
