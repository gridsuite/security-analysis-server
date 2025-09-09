/**
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
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
        testContingencyLimitViolationMapping("10'", 10 * 60, 1200, 1, 1250, TwoSides.TWO, "1'", 1100, 10 * 60, null);
    }

    @Test
    void testContingencyLimitViolationEntityNewFieldsWithPermanentLimitReached() {
        testContingencyLimitViolationMapping(LimitViolationUtils.PERMANENT_LIMIT_NAME, Integer.MAX_VALUE, 1100, 1, 1150, TwoSides.TWO, "10'", 1100, Integer.MAX_VALUE, null);
    }

    @Test
    void testContingencyLimitViolationEntityNewFieldsWithPermanentLimitReachedAndNoTemporaryLimit() {
        testContingencyLimitViolationMapping(LimitViolationUtils.PERMANENT_LIMIT_NAME, Integer.MAX_VALUE, 500, 1, 1000, TwoSides.ONE, null, 500, Integer.MAX_VALUE, null);
    }

    @Test
    void testContingencyLimitViolationEntityNewFieldsWithLastLimitReached() {
        testContingencyLimitViolationMapping("N/A", 0, 1100, 1, 3000, TwoSides.TWO, null, 1100, 0, null);
    }

    @Test
    void testContingencyLimitViolationEntityNewFieldsWithLimitReductionEffective() {
        // for this test to be relevant, "value" needs to be less that "limit"
        testContingencyLimitViolationMapping("10'", 60, 1200, 0.8, 1150, TwoSides.TWO, "1'", 1100, 10 * 60, 60);
    }

    private void testContingencyLimitViolationMapping(String limitName, int acceptableDuration, double limit, double limitReduction, double value, TwoSides side, String expectedNextLimitName, long expectedPatlLimit, Integer expectedAcceptableDuration, Integer expectedUpcomingAcceptableDuration) {
        Network network = EurostagTutorialExample1Factory.createWithFixedCurrentLimits();
        LimitViolation limitViolation = new LimitViolation("NHV1_NHV2_1", "NHV1_NHV2_1_name", LimitViolationType.CURRENT, limitName, acceptableDuration, limit, limitReduction, value, side);

        SubjectLimitViolationEntity subjectLimitViolationEntity = new SubjectLimitViolationEntity("NHV1_NHV2_1", "NHV1_NHV2_1_name");

        ContingencyLimitViolationEntity contingencyLimitViolationEntity = ContingencyLimitViolationEntity.toEntity(network, limitViolation, subjectLimitViolationEntity);

        assertEquals(expectedNextLimitName, contingencyLimitViolationEntity.getNextLimitName());
        assertEquals(expectedPatlLimit, contingencyLimitViolationEntity.getPatlLimit());
        assertEquals(expectedAcceptableDuration, contingencyLimitViolationEntity.getAcceptableDuration());
        assertEquals(expectedUpcomingAcceptableDuration, contingencyLimitViolationEntity.getUpcomingAcceptableDuration());
        assertEquals(100 * limitViolation.getValue() / contingencyLimitViolationEntity.getPatlLimit(), contingencyLimitViolationEntity.getPatlLoading());
    }
}
