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
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.security.*;
import com.powsybl.security.detectors.DefaultLimitViolationDetector;
import com.powsybl.ws.commons.LogUtils;
import org.gridsuite.securityanalysis.server.computation.service.*;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;

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
                        Collections.emptyList(),
                        runContext.getReportNode())
                .thenApply(SecurityAnalysisReport::getResult);
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
    protected void postRun(SecurityAnalysisRunContext runContext, SecurityAnalysisResult securityAnalysisResult) {
        logExcludedEquipmentFromComputation(securityAnalysisResult, runContext);
        logContingencyElementNotFound(runContext);
    }

    private static void logContingencyElementNotFound(SecurityAnalysisRunContext runContext) {
        if (runContext.getReportInfos().reportUuid() != null) {
            List<ContingencyInfos> contingencyInfosList = runContext.getContingencies().stream()
                    .filter(contingencyInfos -> !CollectionUtils.isEmpty(contingencyInfos.getNotFoundElements())).toList();

            if (!CollectionUtils.isEmpty(contingencyInfosList)) {
                ReportNode elementNotFoundSubReporter = runContext.getReportNode().newReportNode()
                    .withMessageTemplate(runContext.getReportInfos().reportUuid().toString() + "notFoundElements", "Elements not found")
                    .add();

                contingencyInfosList.forEach(contingencyInfos -> {
                    String elementsIds = String.join(", ", contingencyInfos.getNotFoundElements());
                    elementNotFoundSubReporter.newReportNode()
                            .withMessageTemplate("contingencyElementNotFound_",
                                    "Cannot find the following equipments ${elementsIds} in contingency ${contingencyId}")
                            .withUntypedValue("elementsIds", elementsIds)
                            .withUntypedValue("contingencyId", contingencyInfos.getId())
                            .withSeverity(TypedValue.WARN_SEVERITY)
                            .add();
                });
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

    private void logExcludedEquipmentFromComputation(SecurityAnalysisResult securityAnalysisResult, SecurityAnalysisRunContext runContext) {

        if (runContext.getReportInfos().reportUuid() != null) {
            Set<String> notFoundElements = runContext.getContingencies().stream()
                    .map(ContingencyInfos::getNotFoundElements)
                    .filter(foundElements -> !CollectionUtils.isEmpty(foundElements))
                    .flatMap(Set::stream)
                    .collect(Collectors.toSet());

            List<Contingency> filteredContingency = filterEquipmentsInContengency(runContext.getContingencies(), notFoundElements);

            //compute the excluded elements
            boolean hasExcludedElements = false;
            for (Contingency contingency : filteredContingency) {
                if (!contingency.getElements().isEmpty()) {
                    hasExcludedElements = true;
                    break;
                }
            }

            if (hasExcludedElements) {
                ReportNode equipmentsDisconnected = runContext.getReportNode().newReportNode()
                        .withMessageTemplate(runContext.getReportInfos().reportUuid().toString() + "disconnectedEquipments", "Disconnected equipments")
                        .add();

                filteredContingency.forEach(contingency -> {
                    if (!contingency.getElements().isEmpty()) {
                        String contingencyName = contingency.getId();
                        String contingencyEquipments = contingency.getElements().stream()
                                .map(ContingencyElement::getId)
                                .collect(Collectors.joining(", "));

                        equipmentsDisconnected.newReportNode()
                                .withMessageTemplate("disconnectedEquipmentsList", "Disconnected equipment in contingency ${contingencyName} : ${contingencyEquipments}")
                                .withUntypedValue("contingencyName", contingencyName)
                                .withUntypedValue("contingencyEquipments", contingencyEquipments)
                                .withSeverity(TypedValue.WARN_SEVERITY)
                                .add();
                    }
                });

                List<Set<String>> setList = new ArrayList<>();
                securityAnalysisResult.getPostContingencyResults()
                                .forEach( postContingencyResult -> {
                                    Set<String> setResult = postContingencyResult.getConnectivityResult().getDisconnectedElements();
                                    setList.add(setResult);
                                });
                Set<String> mergedSet = new HashSet<>();
                setList.forEach(mergedSet::addAll);
                String resultStr = String.join(", ", mergedSet);
                equipmentsDisconnected.newReportNode()
                        .withMessageTemplate("disconnectedElements", "Disconnected equipmentd in contingency ddde")
                        .withUntypedValue("contingencyEquipments", resultStr)
                        .withSeverity(TypedValue.WARN_SEVERITY)
                        .add();
            }

        }
    }

    /**
     * Filters out the equipments in each Contingency object that are present in the exclusion set.
     *
     * @param contingencies A list of Contingency objects. Each Contingency object contains a list of equipments.
     * @param equipmentsToExclude A set of equipment identifiers to be excluded.
     * @return A new list of Contingency objects. Each Contingency object in this list has an equipment list that does not contain any of the equipment in the exclusion set.
     */
    private List<Contingency> filterEquipmentsInContengency(List<ContingencyInfos> contingencies, Set<String> equipmentsToExclude) {
        return contingencies.stream()
                .map(contingency -> {
                    if (contingency.getContingency() == null) {
                        return null;
                    }
                    List<ContingencyElement> filteredEquipments = contingency.getContingency().getElements().stream()
                            .filter(equipment -> !equipmentsToExclude.contains(equipment.getId()))
                            .toList();

                    return new Contingency(contingency.getId(), contingency.getContingency().getName().orElse(""), filteredEquipments);
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }
}
