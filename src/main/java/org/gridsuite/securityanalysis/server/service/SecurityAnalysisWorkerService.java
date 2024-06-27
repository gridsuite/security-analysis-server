/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.report.ReportNode;
import com.powsybl.commons.report.TypedValue;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.criteria.AtLeastOneNominalVoltageCriterion;
import com.powsybl.iidm.criteria.IdentifiableCriterion;
import com.powsybl.iidm.criteria.VoltageInterval;
import com.powsybl.iidm.criteria.duration.IntervalTemporaryDurationCriterion;
import com.powsybl.iidm.criteria.duration.LimitDurationCriterion;
import com.powsybl.iidm.criteria.duration.PermanentDurationCriterion;
import com.powsybl.iidm.network.LimitType;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.security.*;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.security.limitreduction.LimitReduction;
import com.powsybl.ws.commons.LogUtils;
import org.gridsuite.securityanalysis.server.util.LimitReductionConfig;
import org.gridsuite.securityanalysis.server.computation.service.*;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
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

    private final ActionsService actionsService;

    private final LimitReductionConfig limitReductionConfig;

    private Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService, ReportService reportService,
                                         SecurityAnalysisResultService resultService, ObjectMapper objectMapper,
                                         SecurityAnalysisRunnerSupplier securityAnalysisRunnerSupplier, NotificationService notificationService, ExecutionService executionService,
                                         SecurityAnalysisObserver observer, LimitReductionConfig limitReductionConfig) {
        super(networkStoreService, notificationService, reportService, resultService, executionService, observer, objectMapper);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.securityAnalysisFactorySupplier = securityAnalysisRunnerSupplier::getRunner;
        this.limitReductionConfig = limitReductionConfig;
    }

    public void setSecurityAnalysisFactorySupplier(Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier) {
        this.securityAnalysisFactorySupplier = Objects.requireNonNull(securityAnalysisFactorySupplier);
    }

    public SecurityAnalysisResult run(SecurityAnalysisRunContext runContext) {
        try {
            Network network = getNetwork(runContext.getNetworkUuid(),
                    runContext.getVariantId());
            return run(network, runContext, null);
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
    protected CompletableFuture<SecurityAnalysisResult> getCompletableFuture(Network network, SecurityAnalysisRunContext runContext, String provider, UUID resultUuid) {
        SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(provider);
        String variantId = runContext.getVariantId() != null ? runContext.getVariantId() : VariantManagerConstants.INITIAL_VARIANT_ID;

        List<Contingency> contingencies = runContext.getContingencies().stream()
                .map(ContingencyInfos::getContingency)
                .filter(Objects::nonNull)
                .toList();
        List<LimitReduction> limitReductions = getLimitReductions(runContext);

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
                        limitReductions,
                        runContext.getReportNode())
                .thenApply(SecurityAnalysisReport::getResult);
    }

    private List<LimitReduction> getLimitReductions(SecurityAnalysisRunContext runContext) {
        List<IdentifiableCriterion> voltageLevelCriteria = getVoltageLevelCriteria();
        List<LimitDurationCriterion> limitDurationCriteria = getLimitDurationCriteria();

        //TODO add some check to see if the table is consistent ?? Maybe similar to voltage-init ?
        List<List<Double>> rawLimitReductions = runContext.getLimitReductions();
        List<LimitReduction> limitReductions = new ArrayList<>();
        for (int i = 0; i < rawLimitReductions.size(); i++) {
            List<Double> limitReductionRow = rawLimitReductions.get(i);
            IdentifiableCriterion voltageLevelCriterion = voltageLevelCriteria.get(i);
            for (int j = 0; j < limitReductionRow.size(); j++) {
                Double limitReductionValue = limitReductionRow.get(j);
                LimitDurationCriterion limitDurationCriterion = limitDurationCriteria.get(j);
                LimitReduction limitReduction = LimitReduction.builder(LimitType.CURRENT, limitReductionValue)
                        .withNetworkElementCriteria(voltageLevelCriterion)
                        .withLimitDurationCriteria(limitDurationCriterion)
                        .build();
                limitReductions.add(limitReduction);
            }
        }
        return limitReductions;
    }

    private List<LimitDurationCriterion> getLimitDurationCriteria() {
        List<LimitDurationCriterion> limitDurationCriteria = new ArrayList<>();
        List<LimitReductionConfig.LimitDuration> limitDurations = limitReductionConfig.getLimitDurations();
        limitDurationCriteria.add(new PermanentDurationCriterion());
        for (LimitReductionConfig.LimitDuration limitDuration : limitDurations) {
            if (limitDuration.getHighBound() != null) {
                limitDurationCriteria.add(IntervalTemporaryDurationCriterion.between(limitDuration.getLowBound(), limitDuration.getHighBound(), limitDuration.isLowClosed(), limitDuration.isHighClosed()));
            } else {
                limitDurationCriteria.add(IntervalTemporaryDurationCriterion.greaterThan(limitDuration.getLowBound(), limitDuration.isLowClosed()));
            }
        }
        return limitDurationCriteria;
    }

    private List<IdentifiableCriterion> getVoltageLevelCriteria() {
        List<IdentifiableCriterion> voltageLevelCriteria = new ArrayList<>();
        List<LimitReductionConfig.VoltageLevel> voltageLevels = limitReductionConfig.getVoltageLevels();
        for (LimitReductionConfig.VoltageLevel voltageLevel : voltageLevels) {
            voltageLevelCriteria.add(new IdentifiableCriterion(new AtLeastOneNominalVoltageCriterion(VoltageInterval.between(voltageLevel.getLowBound(), voltageLevel.getHighBound(), false, true))));
        }
        return voltageLevelCriteria;
    }

    @Override
    protected void preRun(SecurityAnalysisRunContext runContext) {
        LOGGER.info("Run security analysis on contingency lists: {}", runContext.getContingencyListNames().stream().map(LogUtils::sanitizeParam).toList());

        // enrich context
        List<ContingencyInfos> contingencies = observer.observe("contingencies.fetch", runContext,
                () -> runContext.getContingencyListNames().stream()
                        .map(contingencyListName -> actionsService.getContingencyList(contingencyListName, runContext.getNetworkUuid(), runContext.getVariantId()))
                        .flatMap(List::stream)
                        .toList());

        runContext.setContingencies(contingencies);
    }

    @Override
    protected void postRun(SecurityAnalysisRunContext runContext) {
        if (runContext.getReportInfos().reportUuid() != null) {
            List<ReportNode> notFoundElementReports = new ArrayList<>();
            runContext.getContingencies().stream()
                    .filter(contingencyInfos -> !CollectionUtils.isEmpty(contingencyInfos.getNotFoundElements()))
                    .forEach(contingencyInfos -> {
                        String elementsIds = String.join(", ", contingencyInfos.getNotFoundElements());
                        notFoundElementReports.add(ReportNode.newRootReportNode()
                                .withMessageTemplate("contingencyElementNotFound_" + contingencyInfos.getId() + notFoundElementReports.size(),
                                    String.format("Cannot find the following equipments %s in contingency %s", elementsIds, contingencyInfos.getId()))
                                .withSeverity(TypedValue.WARN_SEVERITY)
                                .build());
                    });
            if (!CollectionUtils.isEmpty(notFoundElementReports)) {
                ReportNode elementNotFoundSubReporter = runContext.getReportNode().newReportNode()
                    .withMessageTemplate(runContext.getReportInfos().reportUuid().toString() + "notFoundElements", "Elements not found")
                    .add();
                notFoundElementReports.forEach(r -> elementNotFoundSubReporter.newReportNode()
                    .withMessageTemplate(r.getMessageKey(), r.getMessageTemplate()).add());
            }
        }
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

    @Bean
    @Override
    public Consumer<Message<String>> consumeRun() {
        return super.consumeRun();
    }

    @Bean
    @Override
    public Consumer<Message<String>> consumeCancel() {
        return super.consumeCancel();
    }
}
