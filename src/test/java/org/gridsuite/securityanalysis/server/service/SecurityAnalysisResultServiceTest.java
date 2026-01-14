/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.gridsuite.securityanalysis.server.dto.ContingencyResultDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.dto.SubjectLimitViolationDTO;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@SpringBootTest
class SecurityAnalysisResultServiceTest {
    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @Test
    void deleteResultPerfTest() {
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(network, resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        SQLStatementCountValidator.reset();

        securityAnalysisResultService.delete(resultUuid);

        // 6 manual delete
        // 1 manual select to get the contingencyUuids, and 4 select at the end for the last delete when applying the cascade
        assertRequestsCount(5, 0, 0, 6);
    }

    @Test
    void insertResultWithoutNetworkTest() {
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(null, resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        securityAnalysisResultService.assertResultExists(resultUuid);

        List<ContingencyResultDTO> contingencyResults = securityAnalysisResultService.findNmKContingenciesResult(resultUuid);
        assertEquals(RESULT.getPostContingencyResults().size(), contingencyResults.size());
        // check fields based on network are actually nullish
        contingencyResults.forEach(this::checkFieldBasedOnNetworkAreNullish);
    }

    private void checkFieldBasedOnNetworkAreNullish(ContingencyResultDTO contingencyResult) {
        assertThat(contingencyResult.getSubjectLimitViolations())
            .extracting(SubjectLimitViolationDTO::getLimitViolation)
            .allSatisfy(lv ->
                assertThat(lv)
                    .as("limitViolation")
                    .satisfies(v -> assertThat(v.getPatlLimit()).isNull())
                    .satisfies(v -> assertThat(v.getPatlLoading()).isNull())
                    .satisfies(v -> assertThat(v.getNextLimitName()).isNull())
                    .satisfies(v -> assertThat(v.getLocationId()).isNull())
                    .satisfies(v -> assertThat(v.getAcceptableDuration()).isZero())
            );
    }

    @AfterEach
    void tearDown() {
        securityAnalysisResultService.deleteAll();
    }
}
