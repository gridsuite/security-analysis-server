/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersDTO;
import org.gridsuite.securityanalysis.server.entities.ParametersContingencyListEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@SpringBootTest
class SecurityAnalysisParametersServiceTest {

    @Autowired
    SecurityAnalysisParametersService securityAnalysisParametersService;

    private static final UUID CONTINGENCY_LIST_ID = UUID.fromString("3f7c9e2a-8b41-4d6a-a1f3-9c5b72e8d4af");
    private static final UUID DEACTIVATED_CONTINGENCY_LIST_ID = UUID.fromString("b8a4f2c1-6d3e-4a9b-92f7-1e5c8d7a3b60");

    @Test
    void toSecurityAnalysisParametersWithContingencyListsTest() {
        // result securityAnalysisParameters should only contain the "activated" contingencyLists
        SecurityAnalysisParametersEntity entity = SecurityAnalysisParametersEntity.builder()
                .contingencyLists(List.of(
                        new ParametersContingencyListEntity(List.of(CONTINGENCY_LIST_ID), "", true),
                        new ParametersContingencyListEntity(List.of(DEACTIVATED_CONTINGENCY_LIST_ID), "", false)
                ))
                .limitReductions(List.of())
                .build();
        SecurityAnalysisParametersDTO parameters = securityAnalysisParametersService.toSecurityAnalysisParameters(entity);
        assertEquals(List.of(CONTINGENCY_LIST_ID), parameters.contingencyListUuids());

        SecurityAnalysisParametersEntity entityWithoutContingencyLists = SecurityAnalysisParametersEntity.builder()
                .contingencyLists(null)
                .limitReductions(List.of())
                .build();
        SecurityAnalysisParametersDTO parametersWithoutContingencyLists = securityAnalysisParametersService.toSecurityAnalysisParameters(entityWithoutContingencyLists);
        assertEquals(List.of(), parametersWithoutContingencyLists.contingencyListUuids());
    }
}
