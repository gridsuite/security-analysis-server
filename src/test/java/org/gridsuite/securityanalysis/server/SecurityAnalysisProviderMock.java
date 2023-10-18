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
import java.util.function.Function;
import java.util.stream.Stream;

import com.powsybl.commons.reporter.Reporter;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.*;
import com.powsybl.security.action.Action;
import com.powsybl.security.strategy.OperatorStrategy;
import org.gridsuite.securityanalysis.server.dto.*;
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

    static final List<Contingency> FAILED_CONTINGENCIES = List.of(
        new Contingency("f1", new TwoWindingsTransformerContingency("t1")),
        new Contingency("f2", new ThreeWindingsTransformerContingency("t2")), // Contingencies are reordered by id
        new Contingency("f3", new StaticVarCompensatorContingency("s3"))
    );

    static final List<Contingency> CONTINGENCIES_VARIANT = List.of(
        new Contingency("l3", new BusbarSectionContingency("l3")),
        new Contingency("l4", new LineContingency("l4"))
    );

    static final LimitViolation LIMIT_VIOLATION_1 = new LimitViolation("l3", LimitViolationType.CURRENT, "l3_name", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_2 = new LimitViolation("vl1", LimitViolationType.HIGH_VOLTAGE, "vl1_name", 0, 400, 1, 410, null);
    static final LimitViolation LIMIT_VIOLATION_3 = new LimitViolation("l6", LimitViolationType.CURRENT, "l6_name", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_4 = new LimitViolation("vl7", LimitViolationType.HIGH_VOLTAGE, "vl7_name", 0, 400, 1, 410, null);
    static final List<LimitViolation> RESULT_LIMIT_VIOLATIONS = List.of(LIMIT_VIOLATION_1, LIMIT_VIOLATION_2, LIMIT_VIOLATION_3);
    static final SecurityAnalysisResult RESULT = new SecurityAnalysisResult(new LimitViolationsResult(List.of(LIMIT_VIOLATION_1)), LoadFlowResult.ComponentResult.Status.CONVERGED,
        Stream.concat(
            CONTINGENCIES.stream().map(contingency -> new PostContingencyResult(contingency, PostContingencyComputationStatus.CONVERGED, RESULT_LIMIT_VIOLATIONS)),
            FAILED_CONTINGENCIES.stream().map(contingency -> new PostContingencyResult(contingency, PostContingencyComputationStatus.FAILED, RESULT_LIMIT_VIOLATIONS)))
        .toList());

    static final SecurityAnalysisResult RESULT_VARIANT = new SecurityAnalysisResult(new LimitViolationsResult(List.of(LIMIT_VIOLATION_3)), LoadFlowResult.ComponentResult.Status.CONVERGED,
        CONTINGENCIES_VARIANT.stream().map(contingency -> new PostContingencyResult(contingency, PostContingencyComputationStatus.CONVERGED, List.of(LIMIT_VIOLATION_4)))
            .toList());

    static final List<ContingencyResultDTO> RESULT_CONTINGENCIES = Stream.concat(
        CONTINGENCIES.stream().map(c -> toContingencyResultDTO(c, LoadFlowResult.ComponentResult.Status.CONVERGED.name(), RESULT_LIMIT_VIOLATIONS)),
        FAILED_CONTINGENCIES.stream().map(c -> toContingencyResultDTO(c, LoadFlowResult.ComponentResult.Status.FAILED.name(), RESULT_LIMIT_VIOLATIONS))
    ).toList();

    /**
     * RESULT_CONTINGENCIES filtered with different criterias START
     */
    static List<ContingencyResultDTO> getResultContingenciesFilteredByContainsNestedSubjectId(String subjectId) {
        return RESULT_CONTINGENCIES.stream().map(r ->
            new ContingencyResultDTO(
                r.getContingency(),
                r.getSubjectLimitViolations().stream()
                    .filter(s -> s.getSubjectId().contains(subjectId))
                    .toList()
            )
        ).toList();
    }

    static List<ContingencyResultDTO> getResultContingenciesFilteredByStartsWithNestedSubjectId(String subjectId) {
        return RESULT_CONTINGENCIES.stream().map(r ->
            new ContingencyResultDTO(
                r.getContingency(),
                r.getSubjectLimitViolations().stream()
                    .filter(s -> s.getSubjectId().startsWith(subjectId))
                    .toList()
            )
        ).toList();
    }
    /**
     * RESULT_CONTINGENCIES filtered with different criterias END
     */

    static final List<SubjectLimitViolationResultDTO> RESULT_CONSTRAINTS = RESULT_LIMIT_VIOLATIONS.stream()
        .map(limitViolation -> toSubjectLimitViolationResultDTO(limitViolation, CONTINGENCIES, FAILED_CONTINGENCIES))
        .toList();

    /**
     * RESULT_CONSTRAINTS filtered with different criterias START
     */
    static List<SubjectLimitViolationResultDTO> getResultConstraintsFilteredByContainsNestedContingencyId(String contingencyId) {
        return RESULT_CONSTRAINTS.stream().map(r ->
            new SubjectLimitViolationResultDTO(
                r.getSubjectId(),
                r.getContingencies().stream()
                    .filter(s -> s.getContingency().getContingencyId().contains(contingencyId))
                    .toList()
            )
        ).toList();
    }

    static List<SubjectLimitViolationResultDTO> getResultConstraintsFilteredByStartsWithNestedContingencyId(String contingencyId) {
        return RESULT_CONSTRAINTS.stream().map(r ->
            new SubjectLimitViolationResultDTO(
                r.getSubjectId(),
                r.getContingencies().stream()
                    .filter(s -> s.getContingency().getContingencyId().startsWith(contingencyId))
                    .toList()
            )
        ).toList();
    }

    static List<SubjectLimitViolationResultDTO> getResultConstraintsWithNestedFilter(Function<ContingencyLimitViolationDTO, Boolean> shouldFilter) {
        return RESULT_CONSTRAINTS.stream().map(r ->
            new SubjectLimitViolationResultDTO(
                r.getSubjectId(),
                r.getContingencies().stream()
                    .filter(shouldFilter::apply)
                    .toList()
            )
        ).toList();
    }
    /**
     * RESULT_CONSTRAINTS filtered with different criterias END
     */

    static final SecurityAnalysisReport REPORT = new SecurityAnalysisReport(RESULT);
    static final SecurityAnalysisReport REPORT_VARIANT = new SecurityAnalysisReport(RESULT_VARIANT);

    static final String VARIANT_1_ID = "variant_1";
    static final String VARIANT_2_ID = "variant_2";
    static final String VARIANT_3_ID = "variant_3";
    static final String VARIANT_TO_STOP_ID = "variant_to_stop";

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

    private static SubjectLimitViolationDTO toSubjectLimitViolationDTO(LimitViolation limitViolation) {
        Double computedLoading = limitViolation.getLimitType().equals(LimitViolationType.CURRENT)
            ? (100 * limitViolation.getValue()) / (limitViolation.getLimit() * limitViolation.getLimitReduction())
            : null;

        return new SubjectLimitViolationDTO(
            limitViolation.getSubjectId(),
            new LimitViolationDTO(
                limitViolation.getLimitType(),
                limitViolation.getLimitName(),
                limitViolation.getSide(),
                limitViolation.getAcceptableDuration(),
                limitViolation.getLimit(),
                limitViolation.getLimitReduction(),
                limitViolation.getValue(),
                computedLoading
            )
        );
    }

    private static SubjectLimitViolationResultDTO toSubjectLimitViolationResultDTO(LimitViolation limitViolation, List<Contingency> convergedContingencies, List<Contingency> failedContingencies) {
        return new SubjectLimitViolationResultDTO(
            limitViolation.getSubjectId(),
            Stream.concat(
                convergedContingencies.stream().map(c -> toContingencyLimitViolationDTO(c, limitViolation, LoadFlowResult.ComponentResult.Status.CONVERGED.name())),
                failedContingencies.stream().map(c -> toContingencyLimitViolationDTO(c, limitViolation, LoadFlowResult.ComponentResult.Status.FAILED.name()))
            ).toList());
    }

    private static ContingencyResultDTO toContingencyResultDTO(Contingency contingency, String status, List<LimitViolation> limitViolations) {
        return new ContingencyResultDTO(
            new ContingencyDTO(
                contingency.getId(),
                status,
                contingency.getElements().stream().map(e -> new ContingencyElementDTO(e.getId(), e.getType())).toList()
            ),
            limitViolations.stream()
                .map(SecurityAnalysisProviderMock::toSubjectLimitViolationDTO)
                .toList()
        );
    }

    private static ContingencyLimitViolationDTO toContingencyLimitViolationDTO(Contingency contingency, LimitViolation limitViolation, String status) {
        Double computedLoading = limitViolation.getLimitType().equals(LimitViolationType.CURRENT)
            ? (100 * limitViolation.getValue()) / (limitViolation.getLimit() * limitViolation.getLimitReduction())
            : null;

        return new ContingencyLimitViolationDTO(
            new ContingencyDTO(
                contingency.getId(),
                status,
                contingency.getElements().stream().map(e -> new ContingencyElementDTO(e.getId(), e.getType())).toList()
            ),
            new LimitViolationDTO(
                limitViolation.getLimitType(),
                limitViolation.getLimitName(),
                limitViolation.getSide(),
                limitViolation.getAcceptableDuration(),
                limitViolation.getLimit(),
                limitViolation.getLimitReduction(),
                limitViolation.getValue(),
                computedLoading
            )
        );
    }
}
