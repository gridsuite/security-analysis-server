/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.actions.server;

import com.powsybl.computation.ComputationManager;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.ContingenciesProvider;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.network.Network;
import com.powsybl.security.*;
import com.powsybl.security.interceptors.SecurityAnalysisInterceptor;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class MockSecurityAnalysisFactory implements SecurityAnalysisFactory {

    static final String CONTINGENCY_LIST_NAME = "list1";

    static final List<Contingency> CONTINGENCIES = List.of(new Contingency("l1", new BranchContingency("l1")),
                                                           new Contingency("l2", new BranchContingency("l2")));

    static final SecurityAnalysisResult RESULT
            = new SecurityAnalysisResult(new LimitViolationsResult(true, Collections.emptyList()),
                                         CONTINGENCIES.stream().map(contingency -> new PostContingencyResult(contingency, true, Collections.emptyList()))
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
                return CompletableFuture.completedFuture(RESULT);
            }
        };
    }
}
