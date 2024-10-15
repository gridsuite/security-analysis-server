/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.service;

import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.RESULT;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@SpringBootTest
class SecurityAnalysisResultServiceTest {

    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @Test
    void deleteResultPerfTest() {
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        SQLStatementCountValidator.reset();

        securityAnalysisResultService.delete(resultUuid);

        // 6 manual delete
        // 1 manual select to get the contingencyUuids, and 4 select at the end for the last delete when applying the cascade
        assertRequestsCount(5, 0, 0, 6);
    }
}
