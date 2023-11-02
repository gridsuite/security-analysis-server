/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import com.powsybl.commons.reporter.Reporter;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.*;
import com.powsybl.security.action.Action;
import com.powsybl.security.strategy.OperatorStrategy;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.powsybl.computation.ComputationManager;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.BusbarSectionContingency;
import com.powsybl.contingency.ContingenciesProvider;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.DanglingLineContingency;
import com.powsybl.contingency.GeneratorContingency;
import com.powsybl.contingency.HvdcLineContingency;
import com.powsybl.contingency.LineContingency;
import com.powsybl.contingency.ShuntCompensatorContingency;
import com.powsybl.contingency.StaticVarCompensatorContingency;
import com.powsybl.contingency.ThreeWindingsTransformerContingency;
import com.powsybl.contingency.TwoWindingsTransformerContingency;
import com.powsybl.iidm.network.Branch;
import com.powsybl.iidm.network.Network;
import com.powsybl.security.interceptors.SecurityAnalysisInterceptor;
import com.powsybl.security.monitor.StateMonitor;
import com.powsybl.security.results.PostContingencyResult;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisProviderMock implements SecurityAnalysisProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisProviderMock.class);

    static final String CONTINGENCY_LIST_NAME = "list1";
    static final String CONTINGENCY_LIST2_NAME = "list2";
    static final String CONTINGENCY_LIST_ERROR_NAME = "listError";
    static final String CONTINGENCY_LIST_NAME_VARIANT = "listVariant";

    static final List<Contingency> CONTINGENCIES = List.of(
        new Contingency("l1", new BranchContingency("l1")),
        new Contingency("l2", new GeneratorContingency("l2")),
        new Contingency("l3", new BusbarSectionContingency("l3")),
        new Contingency("l4", new LineContingency("l4")),
        //new Contingency("l5", new LoadContingency("l5")), //ContingencyElementDeserializer does not handle LOAD
        new Contingency("l6", new HvdcLineContingency("l6")),
        new Contingency("l7", new DanglingLineContingency("l7")),
        new Contingency("l8", new ShuntCompensatorContingency("l8")),
        new Contingency("l9", new TwoWindingsTransformerContingency("l9")),
        new Contingency("la", new ThreeWindingsTransformerContingency("l0")), // Contingencies are reordered by id
        new Contingency("lb", new StaticVarCompensatorContingency("la"))
    );
    static final List<Contingency> CONTINGENCIES_VARIANT = List.of(
        new Contingency("l3", new BusbarSectionContingency("l3")),
        new Contingency("l4", new LineContingency("l4"))
    );

    static final LimitViolation LIMIT_VIOLATION_1 = new LimitViolation("l3", LimitViolationType.CURRENT, "", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_2 = new LimitViolation("vl1", LimitViolationType.HIGH_VOLTAGE, "", 0, 400, 1, 410, null);
    static final LimitViolation LIMIT_VIOLATION_3 = new LimitViolation("l6", LimitViolationType.CURRENT, "", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_4 = new LimitViolation("vl7", LimitViolationType.HIGH_VOLTAGE, "", 0, 400, 1, 410, null);

    static final SecurityAnalysisResult RESULT = new SecurityAnalysisResult(new LimitViolationsResult(List.of(LIMIT_VIOLATION_1)), LoadFlowResult.ComponentResult.Status.CONVERGED,
            CONTINGENCIES.stream().map(contingency -> new PostContingencyResult(contingency, PostContingencyComputationStatus.CONVERGED, List.of(LIMIT_VIOLATION_2)))
            .collect(Collectors.toList()));

    static final SecurityAnalysisResult RESULT_VARIANT = new SecurityAnalysisResult(new LimitViolationsResult(List.of(LIMIT_VIOLATION_3)), LoadFlowResult.ComponentResult.Status.CONVERGED,
        CONTINGENCIES_VARIANT.stream().map(contingency -> new PostContingencyResult(contingency, PostContingencyComputationStatus.CONVERGED, List.of(LIMIT_VIOLATION_4)))
            .collect(Collectors.toList()));

    static final List<ContingencyResultDTO> RESULT_CONTINGENCIES = CONTINGENCIES.stream().map(c ->
        new ContingencyResultDTO(
            new ContingencyDTO(
                c.getId(),
                LoadFlowResult.ComponentResult.Status.CONVERGED.name(),
                c.getElements().stream().map(e -> new ContingencyElementDTO(e.getId(), e.getType())).collect(Collectors.toList())
            ),
            List.of(new SubjectLimitViolationDTO(
                LIMIT_VIOLATION_2.getSubjectId(),
                toLimitViolationDTO(LIMIT_VIOLATION_2)
            )
        ))).collect(Collectors.toList()
    );

    static final List<SubjectLimitViolationResultDTO> RESULT_CONSTRAINTS = List.of(
        new SubjectLimitViolationResultDTO(LIMIT_VIOLATION_1.getSubjectId(), List.of()),
        new SubjectLimitViolationResultDTO(
            LIMIT_VIOLATION_2.getSubjectId(),
            CONTINGENCIES.stream().map(c -> new ContingencyLimitViolationDTO(
                    new ContingencyDTO(c.getId(), LoadFlowResult.ComponentResult.Status.CONVERGED.name(), c.getElements().stream().map(e -> new ContingencyElementDTO(e.getId(), e.getType())).collect(Collectors.toList())),
                    toLimitViolationDTO(LIMIT_VIOLATION_2)
                )
            ).collect(Collectors.toList())
        ));

    static final SecurityAnalysisReport REPORT = new SecurityAnalysisReport(RESULT);
    static final SecurityAnalysisReport REPORT_VARIANT = new SecurityAnalysisReport(RESULT_VARIANT);

    static final String VARIANT_1_ID = "variant_1";
    static final String VARIANT_2_ID = "variant_2";
    static final String VARIANT_3_ID = "variant_3";
    static final String VARIANT_TO_STOP_ID = "variant_to_stop";
    static final String VARIANT_SHOULD_FAIL = "variant_should_fail";
    static final String VARIANT_SHOULD_INTERRUPT = "variant_should_interrupt";
    
    static CountDownLatch countDownLatch;

    public CompletableFuture<SecurityAnalysisReport> run(Network network,
                                                         String workingVariantId,
                                                         LimitViolationDetector detector,
                                                         LimitViolationFilter filter,
                                                         ComputationManager computationManager,
                                                         SecurityAnalysisParameters parameters,
                                                         ContingenciesProvider contingenciesProvider,
                                                         List<SecurityAnalysisInterceptor> interceptors,
                                                         List<OperatorStrategy> operatorStrategies,
                                                         List<Action> actions,
                                                         List<StateMonitor> monitors,
                                                         Reporter reporter) {
        LOGGER.info("Run security analysis mock");
        switch (workingVariantId) {
            case VARIANT_3_ID:
                return CompletableFuture.completedFuture(REPORT_VARIANT);
            case VARIANT_TO_STOP_ID:
                countDownLatch.countDown();
                // creating a long completable future which is here to be canceled
                return new CompletableFuture<SecurityAnalysisReport>().completeOnTimeout(REPORT, 3, TimeUnit.SECONDS);
            case VARIANT_SHOULD_FAIL:
                return new CompletableFuture<SecurityAnalysisReport>().completeAsync(() -> {
                    throw new SecurityAnalysisException(SecurityAnalysisException.Type.COMPUTATION_RUN_ERROR);
                });
            default:
                return CompletableFuture.completedFuture(REPORT);
        }

    }

    @Override
    public String getName() {
        return "SecurityAnalysisMock";
    }

    @Override
    public String getVersion() {
        return "1";
    }

    private static LimitViolationDTO toLimitViolationDTO(LimitViolation limitViolation) {
        Double computedLoading = limitViolation.getLimitType().equals(LimitViolationType.CURRENT)
            ? (100 * limitViolation.getValue()) / (limitViolation.getLimit() * limitViolation.getLimitReduction())
            : null;
        return new LimitViolationDTO(
            limitViolation.getLimitType(),
            limitViolation.getLimitName(),
            limitViolation.getSide(),
            limitViolation.getAcceptableDuration(),
            limitViolation.getLimit(),
            limitViolation.getLimitReduction(),
            limitViolation.getValue(),
            computedLoading
        );
    }
}
