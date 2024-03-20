/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.computation.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Sets;
import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.reporter.Reporter;
import com.powsybl.commons.reporter.ReporterModel;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
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

/**
 * @author Mathieu Deharbe <mathieu.deharbe at rte-france.com
 * @param <S> powsybl Result class specific to the computation
 * @param <R> Run context specific to a computation, including parameters
 * @param <P> powsybl and gridsuite Parameters specifics to the computation
 * @param <T> result service specific to the computation
 */
public abstract class AbstractWorkerService<S, R extends AbstractComputationRunContext<P>, P, T extends AbstractComputationResultService> {
    protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractWorkerService.class);

    protected final Lock lockRunAndCancel = new ReentrantLock();
    protected final ObjectMapper objectMapper;
    protected final Set<UUID> runRequests = Sets.newConcurrentHashSet();
    protected final NetworkStoreService networkStoreService;
    protected final ReportService reportService;
    protected final ExecutionService executionService;
    protected final NotificationService notificationService;
    protected final AbstractComputationObserver<S, P> observer;
    protected final Map<UUID, CompletableFuture<S>> futures = new ConcurrentHashMap<>();
    protected final Map<UUID, CancelContext> cancelComputationRequests = new ConcurrentHashMap<>();
    protected final T resultService;

    protected AbstractWorkerService(NetworkStoreService networkStoreService,
                                    NotificationService notificationService,
                                    ReportService reportService,
                                    T resultService,
                                    ExecutionService executionService,
                                    AbstractComputationObserver<S, P> observer,
                                    ObjectMapper objectMapper) {
        this.networkStoreService = networkStoreService;
        this.notificationService = notificationService;
        this.reportService = reportService;
        this.resultService = resultService;
        this.executionService = executionService;
        this.observer = observer;
        this.objectMapper = objectMapper;
    }

    public PreloadingStrategy getNetworkPreloadingStrategy() {
        return PreloadingStrategy.COLLECTION;
    }

    protected Network getNetwork(UUID networkUuid, String variantId) {
        Network network;
        try {
            network = networkStoreService.getNetwork(networkUuid, getNetworkPreloadingStrategy());
            String variant = StringUtils.isBlank(variantId) ? VariantManagerConstants.INITIAL_VARIANT_ID : variantId;
            network.getVariantManager().setWorkingVariant(variant);
        } catch (PowsyblException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, e.getMessage());
        }
        return network;
    }

    protected void cleanResultsAndPublishCancel(UUID resultUuid, String receiver) {
        resultService.delete(resultUuid);
        notificationService.publishStop(resultUuid, receiver, getComputationType());
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("{} (resultUuid='{}')",
                    NotificationService.getCancelMessage(getComputationType()),
                    resultUuid);
        }
    }

    private void cancelAsync(CancelContext cancelContext) {
        lockRunAndCancel.lock();
        try {
            cancelComputationRequests.put(cancelContext.getResultUuid(), cancelContext);

            // find the completableFuture associated with result uuid
            CompletableFuture<S> future = futures.get(cancelContext.getResultUuid());
            if (future != null) {
                future.cancel(true);  // cancel computation in progress
            }
            cleanResultsAndPublishCancel(cancelContext.getResultUuid(), cancelContext.getReceiver());
        } finally {
            lockRunAndCancel.unlock();
        }
    }

    protected abstract AbstractResultContext<R> fromMessage(Message<String> message);

    @Bean
    public Consumer<Message<String>> consumeRun() {
        return message -> {
            AbstractResultContext<R> resultContext = fromMessage(message);
            try {
                runRequests.add(resultContext.getResultUuid());
                AtomicReference<Long> startTime = new AtomicReference<>();
                startTime.set(System.nanoTime());

                S result = run(resultContext.getRunContext(), resultContext.getResultUuid());

                long nanoTime = System.nanoTime();
                LOGGER.info("Just run in {}s", TimeUnit.NANOSECONDS.toSeconds(nanoTime - startTime.getAndSet(nanoTime)));

                Network network = getNetwork(resultContext.getRunContext().getNetworkUuid(),
                        resultContext.getRunContext().getVariantId());
                observer.observe("results.save", resultContext.getRunContext(), () -> saveResult(network, resultContext, result));

                long finalNanoTime = System.nanoTime();
                LOGGER.info("Stored in {}s", TimeUnit.NANOSECONDS.toSeconds(finalNanoTime - startTime.getAndSet(finalNanoTime)));

                if (result != null) {  // result available
                    notificationService.sendResultMessage(resultContext.getResultUuid(), resultContext.getRunContext().getReceiver());
                    LOGGER.info("{} complete (resultUuid='{}')", getComputationType(), resultContext.getResultUuid());
                } else {  // result not available : stop computation request
                    if (cancelComputationRequests.get(resultContext.getResultUuid()) != null) {
                        cleanResultsAndPublishCancel(resultContext.getResultUuid(), cancelComputationRequests.get(resultContext.getResultUuid()).getReceiver());
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                if (!(e instanceof CancellationException)) {
                    LOGGER.error(NotificationService.getFailedMessage(getComputationType()), e);
                    notificationService.publishFail(
                            resultContext.getResultUuid(), resultContext.getRunContext().getReceiver(),
                            e.getMessage(), resultContext.getRunContext().getUserId(), getComputationType());
                    resultService.delete(resultContext.getResultUuid());
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
        return message -> cancelAsync(CancelContext.fromMessage(message));
    }

    protected abstract void saveResult(Network network, AbstractResultContext<R> resultContext, S result);

    protected void logOnRun(R runContext) {
        LOGGER.info("Run {} computation ...", getComputationType());
    }

    /**
     * if this computation needs extra run data, add them to the run context here
     */
    protected void enrichRunContext(R runContext) { }

    /**
     * if this computation needs extra report operations, override this function and do them here
     */
    protected void reportSpecificOperations(R runContext, Reporter reporter) { }

    protected S run(R runContext, UUID resultUuid) throws Exception {
        logOnRun(runContext);

        enrichRunContext(runContext);

        String provider = runContext.getProvider();
        AtomicReference<Reporter> rootReporter = new AtomicReference<>(Reporter.NO_OP);
        Reporter reporter = Reporter.NO_OP;

        if (runContext.getReportContext().getReportId() != null) {
            final String reportType = runContext.getReportContext().getReportType();
            String rootReporterId = runContext.getReportContext().getReportName() == null ? reportType : runContext.getReportContext().getReportName() + "@" + reportType;
            rootReporter.set(new ReporterModel(rootReporterId, rootReporterId));
            reporter = rootReporter.get().createSubReporter(reportType, String.format("%s (%s)", reportType, provider), "providerToUse", provider);
            // Delete any previous computation logs
            observer.observe("report.delete",
                    runContext, () -> reportService.deleteReport(runContext.getReportContext().getReportId(), reportType));
        }

        Network network = getNetwork(runContext.getNetworkUuid(), runContext.getVariantId());
        CompletableFuture<S> future = runAsync(network, runContext, provider, reporter, resultUuid);

        S result = future == null ? null : observer.observeRun("run", runContext, future::get);
        if (runContext.getReportContext().getReportId() != null) {
            reportSpecificOperations(runContext, reporter);
            observer.observe("report.send", runContext, () -> reportService.sendReport(runContext.getReportContext().getReportId(), rootReporter.get()));
        }
        return result;
    }

    protected CompletableFuture<S> runAsync(
            Network network,
            R runContext,
            String provider,
            Reporter reporter,
            UUID resultUuid) {
        lockRunAndCancel.lock();
        try {
            if (resultUuid != null && cancelComputationRequests.get(resultUuid) != null) {
                return null;
            }
            CompletableFuture<S> future = getCompletableFuture(network, runContext, provider, reporter);
            if (resultUuid != null) {
                futures.put(resultUuid, future);
            }
            return future;
        } finally {
            lockRunAndCancel.unlock();
        }
    }

    protected abstract String getComputationType();

    protected abstract CompletableFuture<S> getCompletableFuture(Network network, R runContext, String provider, Reporter reporter);
}
