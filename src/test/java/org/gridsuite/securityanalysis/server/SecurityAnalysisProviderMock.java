/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.computation.ComputationManager;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.ContingenciesProvider;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.network.Branch;
import com.powsybl.iidm.network.Network;
import com.powsybl.security.*;
import com.powsybl.security.interceptors.SecurityAnalysisInterceptor;
import com.powsybl.security.monitor.StateMonitor;
import com.powsybl.security.results.PostContingencyResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisProviderMock implements SecurityAnalysisProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisProviderMock.class);

    static final String CONTINGENCY_LIST_NAME = "list1";
    static final String CONTINGENCY_LIST2_NAME = "list2";
    static final String CONTINGENCY_LIST_ERROR_NAME = "listError";
    static final String CONTINGENCY_LIST_NAME_VARIANT = "listVariant";

    static final List<Contingency> CONTINGENCIES = List.of(new Contingency("l1", new BranchContingency("l1")),
                                                           new Contingency("l2", new BranchContingency("l2")));
    static final List<Contingency> CONTINGENCIES_VARIANT = List.of(new Contingency("l3", new BranchContingency("l3")),
        new Contingency("l4", new BranchContingency("l4")));

    static final LimitViolation LIMIT_VIOLATION_1 = new LimitViolation("l3", LimitViolationType.CURRENT, "", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_2 = new LimitViolation("vl1", LimitViolationType.HIGH_VOLTAGE, "", 0, 400, 1, 410, null);
    static final LimitViolation LIMIT_VIOLATION_3 = new LimitViolation("l6", LimitViolationType.CURRENT, "", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_4 = new LimitViolation("vl7", LimitViolationType.HIGH_VOLTAGE, "", 0, 400, 1, 410, null);

    static final SecurityAnalysisResult RESULT = new SecurityAnalysisResult(new LimitViolationsResult(true, List.of(LIMIT_VIOLATION_1)),
            CONTINGENCIES.stream().map(contingency -> new PostContingencyResult(contingency, true, List.of(LIMIT_VIOLATION_2)))
            .collect(Collectors.toList()));

    static final SecurityAnalysisResult RESULT_VARIANT = new SecurityAnalysisResult(new LimitViolationsResult(true, List.of(LIMIT_VIOLATION_3)),
        CONTINGENCIES_VARIANT.stream().map(contingency -> new PostContingencyResult(contingency, true, List.of(LIMIT_VIOLATION_4)))
            .collect(Collectors.toList()));

    static final SecurityAnalysisReport REPORT = new SecurityAnalysisReport(RESULT);
    static final SecurityAnalysisReport REPORT_VARIANT = new SecurityAnalysisReport(RESULT_VARIANT);

    static final String VARIANT_1_ID = "variant_1";
    static final String VARIANT_2_ID = "variant_2";
    static final String VARIANT_3_ID = "variant_3";

    public CompletableFuture<SecurityAnalysisReport> run(Network network,
            String workingVariantId,
            LimitViolationDetector detector,
            LimitViolationFilter filter,
            ComputationManager computationManager,
            SecurityAnalysisParameters parameters,
            ContingenciesProvider contingenciesProvider,
            List<SecurityAnalysisInterceptor> interceptors,
            List<StateMonitor> monitors) {
        LOGGER.info("Run security analysis mock");
        return CompletableFuture.completedFuture(workingVariantId.equals(VARIANT_3_ID) ? REPORT_VARIANT : REPORT);
    }

    @Override
    public String getName() {
        return "SecurityAnalysisMock";
    }

    @Override
    public String getVersion() {
        return "1";
    }
}
