/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.reporter.Report;
import com.powsybl.commons.reporter.Reporter;
import com.powsybl.commons.reporter.TypedValue;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.security.LimitViolationFilter;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisReport;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.ws.commons.LogUtils;
import org.gridsuite.securityanalysis.server.computation.service.AbstractResultContext;
import org.gridsuite.securityanalysis.server.computation.service.AbstractWorkerService;
import org.gridsuite.securityanalysis.server.computation.service.NotificationService;
import org.gridsuite.securityanalysis.server.computation.service.ExecutionService;
import org.gridsuite.securityanalysis.server.computation.service.ReportService;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.function.Function;

import static org.gridsuite.securityanalysis.server.computation.service.NotificationService.getFailedMessage;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisService.COMPUTATION_TYPE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisWorkerService extends AbstractWorkerService<SecurityAnalysisResult, SecurityAnalysisRunContext, SecurityAnalysisParameters, SecurityAnalysisResultService> {

    private final ActionsService actionsService;

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

    @Override
    protected CompletableFuture<SecurityAnalysisResult> getCompletableFuture(Network network, SecurityAnalysisRunContext runContext, String provider, Reporter reporter) {
        SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(provider);
        String variantId = runContext.getVariantId() != null ? runContext.getVariantId() : VariantManagerConstants.INITIAL_VARIANT_ID;

        List<Contingency> contingencies = runContext.getContingencies().stream()
                .map(ContingencyInfos::getContingency)
                .filter(Objects::nonNull)
                .toList();

        return securityAnalysisRunner.runAsync(
                        network,
                        variantId,
                        n -> contingencies,
                        runContext.getParameters(),
                        executionService.getComputationManager(),
                        LimitViolationFilter.load(),
                        new DefaultLimitViolationDetector(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        Collections.emptyList(),
                        reporter)
                .thenApply(SecurityAnalysisReport::getResult);
    }

    @Override
    protected void reportSpecificOperations(SecurityAnalysisRunContext runContext, Reporter reporter) {
        List<Report> notFoundElementReports = new ArrayList<>();
        runContext.getContingencies().stream()
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
                    runContext.getReportContext().getReportId().toString() + "notFoundElements",
                    "Elements not found");
            notFoundElementReports.forEach(elementNotFoundSubReporter::report);
        }
    }

    @Override
    protected void logOnRun(SecurityAnalysisRunContext runContext) {
        LOGGER.info("Run security analysis on contingency lists: {}", runContext.getContingencyListNames().stream().map(LogUtils::sanitizeParam).toList());
    }

    @Override
    protected void enrichRunContext(SecurityAnalysisRunContext runContext) {
        List<ContingencyInfos> contingencies = observer.observe("contingencies.fetch", runContext,
                () -> runContext.getContingencyListNames().stream()
                        .map(contingencyListName -> actionsService.getContingencyList(contingencyListName, runContext.getNetworkUuid(), runContext.getVariantId()))
                        .flatMap(List::stream)
                        .toList());

        runContext.setContingencies(contingencies);
    }

    @Override
    protected void saveResult(Network network, AbstractResultContext<SecurityAnalysisRunContext> resultContext, SecurityAnalysisResult result) {
        resultService.insert(
                resultContext.getResultUuid(),
                result,
                result.getPreContingencyResult().getStatus() == LoadFlowResult.ComponentResult.Status.CONVERGED
                        ? SecurityAnalysisStatus.CONVERGED
                        : SecurityAnalysisStatus.DIVERGED);
    }

    @Override
    protected SecurityAnalysisResultContext fromMessage(Message<String> message) {
        return SecurityAnalysisResultContext.fromMessage(message, objectMapper);
    }
}
