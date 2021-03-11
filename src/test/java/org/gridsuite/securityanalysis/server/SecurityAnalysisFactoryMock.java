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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisFactoryMock implements SecurityAnalysisFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisFactoryMock.class);

    static final String CONTINGENCY_LIST_NAME = "list1";
    static final String CONTINGENCY_LIST2_NAME = "list2";
    static final String CONTINGENCY_LIST_ERROR_NAME = "listError";

    static final List<Contingency> CONTINGENCIES = List.of(new Contingency("l1", new BranchContingency("l1")),
                                                           new Contingency("l2", new BranchContingency("l2")));

    static final LimitViolation LIMIT_VIOLATION_1 = new LimitViolation("l3", LimitViolationType.CURRENT, "", 20 * 60, 10, 1, 11, Branch.Side.ONE);
    static final LimitViolation LIMIT_VIOLATION_2 = new LimitViolation("vl1", LimitViolationType.HIGH_VOLTAGE, "", 0, 400, 1, 410, null);

    static final SecurityAnalysisResult RESULT
            = new SecurityAnalysisResult(new LimitViolationsResult(true, List.of(LIMIT_VIOLATION_1)),
                                         CONTINGENCIES.stream().map(contingency -> new PostContingencyResult(contingency, true, List.of(LIMIT_VIOLATION_2)))
                                                                 .collect(Collectors.toList()));

    @Override
    public SecurityAnalysis create(Network network, ComputationManager computationManager, int i) {
        return new SecurityAnalysis() {
            @Override
            public void addInterceptor(SecurityAnalysisInterceptor securityAnalysisInterceptor) {
            }

            @Override
            public boolean removeInterceptor(SecurityAnalysisInterceptor securityAnalysisInterceptor) {
                return false;
            }

            @Override
            public CompletableFuture<SecurityAnalysisResult> run(String s, SecurityAnalysisParameters securityAnalysisParameters, ContingenciesProvider contingenciesProvider) {
                LOGGER.info("Run security analysis mock");
                return CompletableFuture.completedFuture(RESULT);
            }
        };
    }
}
