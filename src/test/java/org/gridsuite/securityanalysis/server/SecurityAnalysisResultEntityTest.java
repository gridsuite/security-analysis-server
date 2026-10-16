/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.violations.LimitViolation;
import com.powsybl.contingency.violations.LimitViolationType;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.TwoSides;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.LimitViolationsResult;
import com.powsybl.security.PostContingencyComputationStatus;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.results.ConnectivityResult;
import com.powsybl.security.results.NetworkResult;
import com.powsybl.security.results.PostContingencyResult;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static com.powsybl.iidm.network.test.EurostagTutorialExample1Factory.NHV1_NHV2_1;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Antoine Bouhours <antoine.bouhours at rte-france.com>
 */
class SecurityAnalysisResultEntityTest {

    @Test
    void toEntityNormalizesStringNullSubjectNames() {
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        SecurityAnalysisResult securityAnalysisResult = new SecurityAnalysisResult(
            new LimitViolationsResult(List.of(
                new LimitViolation(NHV1_NHV2_1, null, LimitViolationType.CURRENT, "10'", 600, 1000, 1, 1100, TwoSides.ONE),
                new LimitViolation(NHV1_NHV2_1, "null", LimitViolationType.CURRENT, "10'", 600, 1000, 1, 1100, TwoSides.ONE)
            )),
            LoadFlowResult.ComponentResult.Status.CONVERGED,
            List.of()
        );

        SecurityAnalysisResultEntity entity = SecurityAnalysisResultEntity.toEntity(network, UUID.randomUUID(), securityAnalysisResult, SecurityAnalysisStatus.CONVERGED);

        assertThat(entity.getSubjectLimitViolations()).hasSize(1);
    }

    @Test
    void toEntityComputesWorstSideOnContingencyLimitViolations() {
        SecurityAnalysisResult securityAnalysisResult = new SecurityAnalysisResult(
            new LimitViolationsResult(List.of()),
            LoadFlowResult.ComponentResult.Status.CONVERGED,
            List.of(new PostContingencyResult(
                new Contingency("contingencyId", new BranchContingency(NHV1_NHV2_1)),
                PostContingencyComputationStatus.CONVERGED,
                new LimitViolationsResult(List.of(
                    new LimitViolation(NHV1_NHV2_1, LimitViolationType.CURRENT, "limitName", 60, 100, 1, 110, TwoSides.ONE),
                    new LimitViolation(NHV1_NHV2_1, LimitViolationType.CURRENT, "limitName", 60, 100, 1, 130, TwoSides.TWO)
                )),
                NetworkResult.empty(),
                ConnectivityResult.empty(),
                1.0
            ))
        );

        SecurityAnalysisResultEntity entity = SecurityAnalysisResultEntity.toEntity(null, UUID.randomUUID(), securityAnalysisResult, SecurityAnalysisStatus.CONVERGED);

        List<ContingencyLimitViolationEntity> contingencyLimitViolations = entity.getContingencies().getFirst().getContingencyLimitViolations();
        assertThat(contingencyLimitViolations).hasSize(2);
        assertThat(contingencyLimitViolations)
            .filteredOn(contingencyLimitViolation -> contingencyLimitViolation.getValue() == 110)
            .singleElement()
            .matches(contingencyLimitViolation -> !contingencyLimitViolation.isWorstSide());
        assertThat(contingencyLimitViolations)
            .filteredOn(contingencyLimitViolation -> contingencyLimitViolation.getValue() == 130)
            .singleElement()
            .matches(ContingencyLimitViolationEntity::isWorstSide);
    }
}
