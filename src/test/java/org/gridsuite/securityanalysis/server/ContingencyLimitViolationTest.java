/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.TwoSides;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.iidm.network.util.LimitViolationUtils;
import com.powsybl.security.LimitViolation;
import com.powsybl.security.LimitViolationBuilder;
import com.powsybl.security.LimitViolationType;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@SpringBootTest
class ContingencyLimitViolationTest {

    @Test
    void testContingencyLimitViolationEntityNewFields() {
        Network network = EurostagTutorialExample1Factory.createWithFixedCurrentLimits();
        LimitViolation limitViolation = new LimitViolation("NHV1_NHV2_1", "NHV1_NHV2_1", LimitViolationType.CURRENT, "10'", 10 * 60, 1200, 1, 1250, TwoSides.TWO);

        SubjectLimitViolationEntity subjectLimitViolationEntity = new SubjectLimitViolationEntity("NHV1_NHV2_1", "NHV1_NHV2_1_name");

        ContingencyLimitViolationEntity contingencyLimitViolationEntity = ContingencyLimitViolationEntity.toEntity(network, limitViolation, subjectLimitViolationEntity);

        assertEquals("1'", contingencyLimitViolationEntity.getNextLimitName());
        assertEquals(1100, contingencyLimitViolationEntity.getPatlLimit());
        assertEquals(100 * limitViolation.getValue() / contingencyLimitViolationEntity.getPatlLimit(), contingencyLimitViolationEntity.getPatlLoading());
    }

    @Test
    void testContingencyLimitViolationEntityNewFieldsWithPermanentLimitReached() {
        Network network = EurostagTutorialExample1Factory.createWithFixedCurrentLimits();
        LimitViolation limitViolation = new LimitViolation("NHV1_NHV2_1", "NHV1_NHV2_1", LimitViolationType.CURRENT, LimitViolationUtils.PERMANENT_LIMIT_NAME, 10 * 60, 1100, 1, 1150, TwoSides.TWO);

        SubjectLimitViolationEntity subjectLimitViolationEntity = new SubjectLimitViolationEntity("NHV1_NHV2_1", "NHV1_NHV2_1_name");

        ContingencyLimitViolationEntity contingencyLimitViolationEntity = ContingencyLimitViolationEntity.toEntity(network, limitViolation, subjectLimitViolationEntity);

        assertEquals("10'", contingencyLimitViolationEntity.getNextLimitName());
        assertEquals(1100, contingencyLimitViolationEntity.getPatlLimit());
        assertEquals(100 * limitViolation.getValue() / contingencyLimitViolationEntity.getPatlLimit(), contingencyLimitViolationEntity.getPatlLoading());
    }
}
