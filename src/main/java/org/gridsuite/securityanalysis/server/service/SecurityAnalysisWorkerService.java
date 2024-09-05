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
import com.powsybl.iidm.network.NetworkFactory;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.serde.NetworkSerDe;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.security.*;
import com.powsybl.security.limitreduction.LimitReduction;
import com.powsybl.ws.commons.LogUtils;
import com.powsybl.ws.commons.computation.service.*;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.LimitReductionsByVoltageLevel;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

import static com.powsybl.ws.commons.computation.service.NotificationService.getFailedMessage;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisService.COMPUTATION_TYPE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisWorkerService extends AbstractWorkerService<SecurityAnalysisResult, SecurityAnalysisRunContext, SecurityAnalysisParametersDTO, SecurityAnalysisResultService> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisWorkerService.class);
    private final ActionsService actionsService;

    private final LimitReductionService limitReductionService;

    private Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier;

    public SecurityAnalysisWorkerService(NetworkStoreService networkStoreService, ActionsService actionsService, ReportService reportService,
                                         SecurityAnalysisResultService resultService, ObjectMapper objectMapper,
                                         SecurityAnalysisRunnerSupplier securityAnalysisRunnerSupplier, NotificationService notificationService, ExecutionService executionService,
                                         SecurityAnalysisObserver observer, LimitReductionService limitReductionService) {
        super(networkStoreService, notificationService, reportService, resultService, executionService, observer, objectMapper);
        this.actionsService = Objects.requireNonNull(actionsService);
        this.securityAnalysisFactorySupplier = securityAnalysisRunnerSupplier::getRunner;
        this.limitReductionService = limitReductionService;
    }

    public void setSecurityAnalysisFactorySupplier(Function<String, SecurityAnalysis.Runner> securityAnalysisFactorySupplier) {
        this.securityAnalysisFactorySupplier = Objects.requireNonNull(securityAnalysisFactorySupplier);
    }

    public SecurityAnalysisResult run(SecurityAnalysisRunContext runContext) {
        try {
            Network network = getNetwork(runContext.getNetworkUuid(),
                    runContext.getVariantId());
            runContext.setNetwork(network);
            AtomicReference<ReportNode> rootReporter = new AtomicReference<>();
            return run(runContext, null, rootReporter);
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
    protected CompletableFuture<SecurityAnalysisResult> getCompletableFuture(SecurityAnalysisRunContext runContext, String provider, UUID resultUuid) {
        SecurityAnalysis.Runner securityAnalysisRunner = securityAnalysisFactorySupplier.apply(provider);
        String variantId = runContext.getVariantId() != null ? runContext.getVariantId() : VariantManagerConstants.INITIAL_VARIANT_ID;

        List<Contingency> contingencies = runContext.getContingencies().stream()
                .map(ContingencyInfos::getContingency)
                .filter(Objects::nonNull)
                .toList();
        List<LimitReduction> limitReductions = createLimitReductions(runContext);

        Network network = runContext.getNetwork();
        // FIXME: Remove this part when multithread variant access is implemented in the network-store
        if (runContext.getProvider().equals("OpenLoadFlow")) {
            long startTime = System.nanoTime();
            Network originalNetwork = runContext.getNetwork();
            String originalVariant = originalNetwork.getVariantManager().getWorkingVariantId();
            originalNetwork.getVariantManager().setWorkingVariant(variantId);

            network = NetworkSerDe.copy(originalNetwork, NetworkFactory.find("Default"));
            if (!variantId.equals(VariantManagerConstants.INITIAL_VARIANT_ID)) {
                network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, variantId);
            }
            LOGGER.info("Network copied to iidm-impl in {} ms", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startTime));
            originalNetwork.getVariantManager().setWorkingVariant(originalVariant);
        }

        SecurityAnalysisRunParameters runParameters = new SecurityAnalysisRunParameters()
                .setSecurityAnalysisParameters(runContext.getParameters().securityAnalysisParameters())
                .setComputationManager(executionService.getComputationManager())
                .setFilter(LimitViolationFilter.load())
                .setLimitReductions(limitReductions)
                .setReportNode(runContext.getReportNode());

        return securityAnalysisRunner.runAsync(
                        network,
                        variantId,
                        n -> contingencies,
                        runParameters)
                .thenApply(SecurityAnalysisReport::getResult);
    }

    private List<LimitReduction> createLimitReductions(SecurityAnalysisRunContext runContext) {
        List<LimitReduction> limitReductions = new ArrayList<>(limitReductionService.getVoltageLevels().size() * limitReductionService.getLimitDurations().size());

        limitReductionService.createLimitReductions(runContext.getParameters().limitReductions()).forEach(limitReduction -> {
            LimitReductionsByVoltageLevel.VoltageLevel voltageLevel = limitReduction.getVoltageLevel();
            IdentifiableCriterion voltageLevelCriterion = new IdentifiableCriterion(new AtLeastOneNominalVoltageCriterion(VoltageInterval.between(voltageLevel.getLowBound(), voltageLevel.getHighBound(), false, true)));
            limitReductions.add(createLimitReduction(voltageLevelCriterion, new PermanentDurationCriterion(), limitReduction.getPermanentLimitReduction()));
            limitReduction.getTemporaryLimitReductions().forEach(temporaryLimitReduction -> {
                LimitDurationCriterion limitDurationCriterion;
                LimitReductionsByVoltageLevel.LimitDuration limitDuration = temporaryLimitReduction.getLimitDuration();
                if (limitDuration.getHighBound() != null) {
                    limitDurationCriterion = IntervalTemporaryDurationCriterion.between(limitDuration.getLowBound(), limitDuration.getHighBound(), limitDuration.isLowClosed(), limitDuration.isHighClosed());
                } else {
                    limitDurationCriterion = IntervalTemporaryDurationCriterion.greaterThan(limitDuration.getLowBound(), limitDuration.isLowClosed());
                }
                limitReductions.add(createLimitReduction(voltageLevelCriterion, limitDurationCriterion, temporaryLimitReduction.getReduction()));
            });
        });

        return limitReductions;
    }

    private LimitReduction createLimitReduction(IdentifiableCriterion voltageLevelCriterion, LimitDurationCriterion limitDurationCriterion, double value) {
        return LimitReduction.builder(LimitType.CURRENT, value)
                .withNetworkElementCriteria(voltageLevelCriterion)
                .withLimitDurationCriteria(limitDurationCriterion)
                .build();
    }

    @Override
    protected void preRun(SecurityAnalysisRunContext runContext) {
        LOGGER.info("Run security analysis on contingency lists: {}", runContext.getContingencyListNames().stream().map(LogUtils::sanitizeParam).toList());

        List<ContingencyInfos> contingencies = observer.observe("contingencies.fetch", runContext,
                () ->
                    actionsService.getContingencyList(runContext.getContingencyListNames(), runContext.getNetworkUuid(), runContext.getVariantId())
                );

        runContext.setContingencies(contingencies);
    }

    @Override
    protected void postRun(SecurityAnalysisRunContext runContext, AtomicReference<ReportNode> rootReportNode, SecurityAnalysisResult ignoredResult) {
        if (runContext.getReportInfos().reportUuid() != null) {
            logContingencyEquipmentsNotConnected(runContext);
            logContingencyEquipmentsNotFound(runContext);
        }
        super.postRun(runContext, rootReportNode, ignoredResult);
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

    private static void logContingencyEquipmentsNotFound(SecurityAnalysisRunContext runContext) {
        List<ContingencyInfos> contingencyInfosList = runContext.getContingencies().stream()
                .filter(contingencyInfos -> !CollectionUtils.isEmpty(contingencyInfos.getNotFoundElements())).toList();

        if (contingencyInfosList.isEmpty()) {
            return;
        }

        ReportNode elementsNotFoundSubReporter = runContext.getReportNode().newReportNode()
                .withMessageTemplate("notFoundEquipments", "Equipments not found")
                .add();

        contingencyInfosList.forEach(contingencyInfos -> {
            String elementsIds = String.join(", ", contingencyInfos.getNotFoundElements());
            elementsNotFoundSubReporter.newReportNode()
                    .withMessageTemplate("contingencyEquipmentNotFound",
                            "Cannot find the following equipments ${elementsIds} in contingency ${contingencyId}")
                    .withUntypedValue("elementsIds", elementsIds)
                    .withUntypedValue("contingencyId", contingencyInfos.getId())
                    .withSeverity(TypedValue.WARN_SEVERITY)
                    .add();
        });
    }

    private void logContingencyEquipmentsNotConnected(SecurityAnalysisRunContext runContext) {
        List<ContingencyInfos> contingencyInfosList = runContext.getContingencies().stream()
                .filter(contingencyInfos -> !CollectionUtils.isEmpty(contingencyInfos.getNotConnectedElements())).toList();

        if (contingencyInfosList.isEmpty()) {
            return;
        }

        ReportNode elementsNotConnectedSubReporter = runContext.getReportNode().newReportNode()
                .withMessageTemplate("notConnectedEquipments", "Equipments not connected")
                .add();

        contingencyInfosList.forEach(contingencyInfos -> {
            String elementsIds = String.join(", ", contingencyInfos.getNotConnectedElements());
            elementsNotConnectedSubReporter.newReportNode()
                    .withMessageTemplate("contingencyEquipmentNotConnected",
                            "The following equipments ${elementsIds} in contingency ${contingencyId} are not connected")
                    .withUntypedValue("elementsIds", elementsIds)
                    .withUntypedValue("contingencyId", contingencyInfos.getId())
                    .withSeverity(TypedValue.WARN_SEVERITY)
                    .add();
        });
    }

}
