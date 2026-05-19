/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.contingency.violations.LimitViolation;
import com.powsybl.contingency.violations.LimitViolationType;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.TwoSides;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.LimitViolationsResult;
import com.powsybl.security.SecurityAnalysisResult;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
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
}
