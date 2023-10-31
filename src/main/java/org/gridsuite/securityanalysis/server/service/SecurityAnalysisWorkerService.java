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
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.LimitViolationFilter;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisReport;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.ws.commons.LogUtils;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
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

    private SecurityAnalysisResultService securityAnalysisResultService;

    private ObjectMapper objectMapper;

    private Map<UUID, CompletableFuture<SecurityAnalysisResult>> futures = new ConcurrentHashMap<>();

    private Map<UUID, SecurityAnalysisCancelContext> cancelComputationRequests = new ConcurrentHashMap<>();

    private Set<UUID> runRequests = Sets.newConcurrentHashSet();

    private Lock lockRunAndCancelAS = new ReentrantLock();

    private Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier;

    private SecurityAnalysisExecutionService securityAnalysisExecutionService;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService, ReportService reportService,
                                         SecurityAnalysisResultService resultRepository, ObjectMapper objectMapper,
                                         SecurityAnalysisRunnerSupplier securityAnalysisRunnerSupplier, NotificationService notificationService, SecurityAnalysisExecutionService securityAnalysisExecutionService) {
        this.networkStoreService = Objects.requireNonNull(networkStoreService);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.reportService = Objects.requireNonNull(reportService);
        this.securityAnalysisResultService = Objects.requireNonNull(resultRepository);
        this.objectMapper = Objects.requireNonNull(objectMapper);
        this.notificationService = Objects.requireNonNull(notificationService);
        this.securityAnalysisExecutionService = Objects.requireNonNull(securityAnalysisExecutionService);
        this.securityAnalysisFactorySupplier = securityAnalysisRunnerSupplier::getRunner;
    }

    public void setSecurityAnalysisFactorySupplier(Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier) {
        this.securityAnalysisFactorySupplier = Objects.requireNonNull(securityAnalysisFactorySupplier);
    }

    private Network getNetwork(UUID networkUuid) {
        try {
            return networkStoreService.getNetwork(networkUuid, PreloadingStrategy.COLLECTION);
        } catch (PowsyblException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
    }

    private Network getNetwork(UUID networkUuid, List<UUID> otherNetworkUuids) {
        Network network = getNetwork(networkUuid);
        if (otherNetworkUuids.isEmpty()) {
            return network;
        } else {
            List<Network> networks = new ArrayList<>();
            List<Network> otherNetworks = otherNetworkUuids
                .stream()
                .map(this::getNetwork)
                .collect(Collectors.toList());

            networks.add(network);
            networks.addAll(otherNetworks);

            MergingView mergingView = MergingView.create("merge", "iidm");
            mergingView.merge(networks.toArray(new Network[0]));

            return mergingView;
        }
    }

    public SecurityAnalysisResult run(SecurityAnalysisRunContext context) {
        try {
            return run(context, null);
        } catch (ExecutionException | InterruptedException e) {
            throw new CancellationException(e.getMessage());
        }
    }

    private CompletableFuture<SecurityAnalysisResult> runASAsync(SecurityAnalysisRunContext context,
                                                                 SecurityAnalysis.Runner securityAnalysisRunner,
                                                                 Network network,
                                                                 List<Contingency> contingencies,
                                                                 Reporter reporter,
                                                                 UUID resultUuid) {
        lockRunAndCancelAS.lock();
        try {
            if (resultUuid != null && cancelComputationRequests.get(resultUuid) != null) {
                return null;
            }
            String variantId = context.getVariantId() != null ? context.getVariantId() : VariantManagerConstants.INITIAL_VARIANT_ID;

            CompletableFuture<SecurityAnalysisResult> future = securityAnalysisRunner.runAsync(
                network,
                variantId,
                n -> contingencies,
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
        securityAnalysisResultService.delete(resultUuid);
        notificationService.emitStopAnalysisMessage(resultUuid.toString(), receiver);
        LOGGER.info(CANCEL_MESSAGE + " (resultUuid='{}')", resultUuid);
    }

    private SecurityAnalysisResult run(SecurityAnalysisRunContext context, UUID resultUuid) throws ExecutionException, InterruptedException {
        Objects.requireNonNull(context);

        LOGGER.info("Run security analysis on contingency lists: {}", context.getContingencyListNames().stream().map(LogUtils::sanitizeParam).collect(Collectors.toList()));

        Network network = getNetwork(context.getNetworkUuid(), context.getOtherNetworkUuids());

        List<Contingency> contingencies = context.getContingencyListNames().stream()
            .map(contingencyListName -> actionsService.getContingencyList(contingencyListName, context.getNetworkUuid(), context.getVariantId()))
            .flatMap(List::stream)
            .collect(Collectors.toList());

        SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(context.getProvider());

        Reporter rootReporter = Reporter.NO_OP;
        Reporter reporter = Reporter.NO_OP;
        if (context.getReportUuid() != null) {
            String rootReporterId = context.getReporterId() == null ? AS_TYPE_REPORT : context.getReporterId() + "@" + AS_TYPE_REPORT;
            rootReporter = new ReporterModel(rootReporterId, rootReporterId);
            reporter = rootReporter.createSubReporter(AS_TYPE_REPORT, AS_TYPE_REPORT + " (${providerToUse})", "providerToUse", securityAnalysisRunner.getName());
        }

        CompletableFuture<SecurityAnalysisResult> future = runASAsync(context, securityAnalysisRunner, network, contingencies, reporter, resultUuid);

        SecurityAnalysisResult result = future == null ? null : future.get();
        if (context.getReportUuid() != null) {
            Reporter finalRootReporter = rootReporter;
            reportService.sendReport(context.getReportUuid(), finalRootReporter);
        }
        return result;
    }

    @Bean
    public Consumer<Message<String>> consumeRun() {
        return message -> {
            SecurityAnalysisResultContext resultContext = SecurityAnalysisResultContext.fromMessage(message, objectMapper);
            try {
                runRequests.add(resultContext.getResultUuid());
                AtomicReference<Long> startTime = new AtomicReference<>();

                startTime.set(System.nanoTime());
                SecurityAnalysisResult result = run(resultContext.getRunContext(), resultContext.getResultUuid());
                long nanoTime = System.nanoTime();
                LOGGER.info("Just run in {}s", TimeUnit.NANOSECONDS.toSeconds(nanoTime - startTime.getAndSet(nanoTime)));

                securityAnalysisResultService.insert(
                    resultContext.getResultUuid(),
                    result,
                    result.getPreContingencyResult().getStatus() == LoadFlowResult.ComponentResult.Status.CONVERGED
                        ? SecurityAnalysisStatus.CONVERGED
                        : SecurityAnalysisStatus.DIVERGED);

                long finalNanoTime = System.nanoTime();
                LOGGER.info("Stored in {}s", TimeUnit.NANOSECONDS.toSeconds(finalNanoTime - startTime.getAndSet(finalNanoTime)));

                if (result != null) {  // result available
                    notificationService.emitAnalysisResultsMessage(resultContext.getResultUuid().toString(), resultContext.getRunContext().getReceiver());
                    LOGGER.info("Security analysis complete (resultUuid='{}')", resultContext.getResultUuid());
                } else {  // result not available : stop computation request
                    if (cancelComputationRequests.get(resultContext.getResultUuid()) != null) {
                        cleanASResultsAndPublishCancel(resultContext.getResultUuid(), cancelComputationRequests.get(resultContext.getResultUuid()).getReceiver());
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                LOGGER.error(FAIL_MESSAGE, e);
                if (!(e instanceof CancellationException)) {
                    notificationService.emitFailAnalysisMessage(resultContext.getResultUuid().toString(),
                        resultContext.getRunContext().getReceiver(),
                        e.getMessage());
                    securityAnalysisResultService.delete(resultContext.getResultUuid());
                }
            } finally {
                futures.remove(resultContext.getResultUuid());
                cancelComputationRequests.remove(resultContext.getResultUuid());
                runRequests.remove(resultContext.getResultUuid());
            }
        };
    }

    @Bean
    public Consumer<Message<String>> consumeCancel() {
        return message -> cancelASAsync(SecurityAnalysisCancelContext.fromMessage(message));
    }
}
