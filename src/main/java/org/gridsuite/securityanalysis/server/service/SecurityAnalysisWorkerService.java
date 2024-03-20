/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.reporter.Report;
import com.powsybl.commons.reporter.Reporter;
import com.powsybl.commons.reporter.ReporterModel;
import com.powsybl.commons.reporter.TypedValue;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.LimitViolationFilter;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisReport;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.ws.commons.LogUtils;
import org.gridsuite.securityanalysis.server.computation.service.AbstractWorkerService;
import org.gridsuite.securityanalysis.server.computation.service.NotificationService;
import org.gridsuite.securityanalysis.server.computation.service.ExecutionService;
import org.gridsuite.securityanalysis.server.computation.service.ReportService;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

import static org.gridsuite.securityanalysis.server.computation.service.NotificationService.getFailedMessage;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisService.COMPUTATION_TYPE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisWorkerService extends AbstractWorkerService<SecurityAnalysisResult, SecurityAnalysisRunContext, SecurityAnalysisParameters, SecurityAnalysisResultService> {

    private ActionsService actionsService;

    private Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService, ReportService reportService,
                                         SecurityAnalysisResultService resultService, ObjectMapper objectMapper,
                                         SecurityAnalysisRunnerSupplier securityAnalysisRunnerSupplier, NotificationService notificationService, ExecutionService executionService,
                                         SecurityAnalysisObserver observer) {
        super(networkStoreService, notificationService, reportService, resultService, executionService, observer, objectMapper);
        this.actionsService = Objects.requireNonNull(actionsService);
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

    public SecurityAnalysisResult run(SecurityAnalysisRunContext context) {
        try {
            return run(context, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } catch (Exception e) {
            LOGGER.error(getFailedMessage(getComputationType()), e);
            return null;
        }
    }

    @Override
    protected String getComputationType() {
        return COMPUTATION_TYPE;
    }

    private CompletableFuture<SecurityAnalysisResult> runASAsync(SecurityAnalysisRunContext context,
                                                                 SecurityAnalysis.Runner securityAnalysisRunner,
                                                                 Network network,
                                                                 List<Contingency> contingencies,
                                                                 Reporter reporter,
                                                                 UUID resultUuid) {
        lockRunAndCancel.lock();
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
                executionService.getComputationManager(),
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
            lockRunAndCancel.unlock();
        }
    }

    private SecurityAnalysisResult run(SecurityAnalysisRunContext context, UUID resultUuid) throws Exception {
        Objects.requireNonNull(context);

        LOGGER.info("Run security analysis on contingency lists: {}", context.getContingencyListNames().stream().map(LogUtils::sanitizeParam).toList());

        Network network = observer.observe("network.load", context, () -> getNetwork(context.getNetworkUuid()));

        List<ContingencyInfos> contingencies = observer.observe("contingencies.fetch", context,
            () -> context.getContingencyListNames().stream()
                .map(contingencyListName -> actionsService.getContingencyList(contingencyListName, context.getNetworkUuid(), context.getVariantId()))
                .flatMap(List::stream)
                .toList());

        SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(context.getProvider());

        AtomicReference<Reporter> rootReporter = new AtomicReference<>(Reporter.NO_OP);
        Reporter reporter = Reporter.NO_OP;

        if (context.getReportContext().getReportId() != null) {
            final String reportType = context.getReportContext().getReportType();
            String rootReporterId = context.getReportContext().getReportName() == null ?
                    reportType :
                    context.getReportContext().getReportName() + "@" + reportType;
            rootReporter.set(new ReporterModel(rootReporterId, rootReporterId));
            reporter = rootReporter.get().createSubReporter(reportType, reportType + " (${providerToUse})", "providerToUse", securityAnalysisRunner.getName());
            // Delete any previous SA computation logs
            observer.observe("report.delete",
                    context, () -> reportService.deleteReport(context.getReportContext().getReportId(), reportType));
        }

        CompletableFuture<SecurityAnalysisResult> future = runASAsync(context,
                securityAnalysisRunner,
                network,
                contingencies.stream()
                        .map(ContingencyInfos::getContingency)
                        .filter(Objects::nonNull)
                        .toList(),
                reporter,
                resultUuid);

        SecurityAnalysisResult result = future == null ? null : observer.observeRun("run", context, future::get);
        if (context.getReportContext().getReportId() != null) {
            List<Report> notFoundElementReports = new ArrayList<>();
            contingencies.stream()
                    .filter(contingencyInfos -> !CollectionUtils.isEmpty(contingencyInfos.getNotFoundElements()))
                    .forEach(contingencyInfos -> {
                        String elementsIds = String.join(", ", contingencyInfos.getNotFoundElements());
                        notFoundElementReports.add(Report.builder()
                                .withKey("contingencyElementNotFound_" + contingencyInfos.getId() + notFoundElementReports.size())
                                .withDefaultMessage(String.format("Cannot find the following equipments %s in contingency %s", elementsIds, contingencyInfos.getId()))
                                .withSeverity(TypedValue.WARN_SEVERITY)
                                .build());
                    });
            if (!CollectionUtils.isEmpty(notFoundElementReports)) {
                Reporter elementNotFoundSubReporter = reporter.createSubReporter(
                        context.getReportContext().getReportId().toString() + "notFoundElements",
                        "Elements not found");
                notFoundElementReports.forEach(elementNotFoundSubReporter::report);
            }
            observer.observe("report.send",
                    context, () -> reportService.sendReport(context.getReportContext().getReportId(), rootReporter.get()));
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

                observer.observe("results.save", resultContext.getRunContext(), () -> resultService.insert(
                    resultContext.getResultUuid(),
                    result,
                    result.getPreContingencyResult().getStatus() == LoadFlowResult.ComponentResult.Status.CONVERGED
                        ? SecurityAnalysisStatus.CONVERGED
                        : SecurityAnalysisStatus.DIVERGED));

                long finalNanoTime = System.nanoTime();
                LOGGER.info("Stored in {}s", TimeUnit.NANOSECONDS.toSeconds(finalNanoTime - startTime.getAndSet(finalNanoTime)));

                if (result != null) {  // result available
                    notificationService.sendResultMessage(resultContext.getResultUuid(), resultContext.getRunContext().getReceiver());
                    LOGGER.info("Security analysis complete (resultUuid='{}')", resultContext.getResultUuid());
                } else {  // result not available : stop computation request
                    if (cancelComputationRequests.get(resultContext.getResultUuid()) != null) {
                        cleanResultsAndPublishCancel(resultContext.getResultUuid(), cancelComputationRequests.get(resultContext.getResultUuid()).getReceiver());
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                if (!(e instanceof CancellationException)) {
                    LOGGER.error(getFailedMessage(getComputationType()), e);
                    notificationService.publishFail(resultContext.getResultUuid(),
                            resultContext.getRunContext().getReceiver(),
                            e.getMessage(),
                            resultContext.getRunContext().getUserId(),
                            getComputationType());
                    resultService.delete(resultContext.getResultUuid());
                }
            } finally {
                futures.remove(resultContext.getResultUuid());
                cancelComputationRequests.remove(resultContext.getResultUuid());
                runRequests.remove(resultContext.getResultUuid());
            }
        };
    }
}
