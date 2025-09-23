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
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.junit.jupiter.api.Test;

import static com.powsybl.iidm.network.test.EurostagTutorialExample1Factory.NGEN_NHV1;
import static com.powsybl.iidm.network.test.EurostagTutorialExample1Factory.NHV1_NHV2_1;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Caroline Jeandat <caroline.jeandat at rte-france.com>
 */
abstract class AbstractLimitViolationTest<T extends AbstractLimitViolationEntity> {

    @Test
    void testLimitViolationEntityNewFields() {
        testLimitViolationMapping("10'", 10 * 60, 1200, 1, 1250, TwoSides.TWO, "1'", 1100, 10 * 60, null);
    }

    @Test
    void testLimitViolationEntityNewFieldsWithPermanentLimitReached() {
        testLimitViolationMapping(LimitViolationUtils.PERMANENT_LIMIT_NAME, Integer.MAX_VALUE, 1100, 1, 1150,
                TwoSides.TWO, "10'", 1100, Integer.MAX_VALUE, null);
    }

    @Test
    void testLimitViolationEntityNewFieldsWithPermanentLimitReachedAndNoTemporaryLimit() {
        testLimitViolationMapping(LimitViolationUtils.PERMANENT_LIMIT_NAME, Integer.MAX_VALUE, 500, 1, 1000,
                TwoSides.ONE, null, 500, Integer.MAX_VALUE, null);
    }

    @Test
    void testLimitViolationEntityNewFieldsWithLastLimitReached() {
        testLimitViolationMapping("N/A", 0, 1100, 1, 3000, TwoSides.TWO, null, 1100, 0, null);
    }

    @Test
    void testLimitViolationEntityNewFieldsWithLimitReductionEffective() {
        // for this test to be relevant, "value" needs to be less that "limit"
        testLimitViolationMapping("10'", 60, 1200, 0.8, 1150, TwoSides.TWO, "1'", 1100, 10 * 60, 60);
    }

    @Test
    void test2wtLimitViolationEntityNewFieldsWithLimitReductionEffective() {
        // for this test to be relevant, "value" needs to be less that "limit"
        Network network = EurostagTutorialExample1Factory.createWithFixedCurrentLimits();
        // create limit set for two windings transformer
        network.getTwoWindingsTransformer(NGEN_NHV1).getOrCreateSelectedOperationalLimitsGroup1().newCurrentLimits()
                .setPermanentLimit(100)
                .beginTemporaryLimit()
                .setName("10'")
                .setValue(200)
                .setAcceptableDuration(60 * 10)
                .endTemporaryLimit()
                .beginTemporaryLimit()
                .setName("1'")
                .setValue(300)
                .setAcceptableDuration(60)
                .endTemporaryLimit()
                .beginTemporaryLimit()
                .setName("N/A")
                .setValue(Double.MAX_VALUE)
                .setAcceptableDuration(0)
                .endTemporaryLimit()
                .add();

        LimitViolation limitViolation = new LimitViolation(NGEN_NHV1, "NGEN_NHV1_name", LimitViolationType.CURRENT,
                "10'", 60, 200, 0.8, 180, TwoSides.ONE);

        SubjectLimitViolationEntity subjectLimitViolationEntity = new SubjectLimitViolationEntity(NGEN_NHV1,
                "NGEN_NHV1_name");

        AbstractLimitViolationEntity limitViolationEntity = createLimitViolationEntity(network, limitViolation,
                subjectLimitViolationEntity);

        assertEquals("1'", limitViolationEntity.getNextLimitName());
        assertEquals(100, limitViolationEntity.getPatlLimit());
        assertEquals(60 * 10, limitViolationEntity.getAcceptableDuration());
        assertEquals(60, limitViolationEntity.getUpcomingAcceptableDuration());
        assertEquals(100 * limitViolation.getValue() / limitViolationEntity.getPatlLimit(),
                limitViolationEntity.getPatlLoading());
    }

    private void testLimitViolationMapping(String limitName, int acceptableDuration, double limit,
            double limitReduction, double value, TwoSides side, String expectedNextLimitName, long expectedPatlLimit,
            Integer expectedAcceptableDuration, Integer expectedUpcomingAcceptableDuration) {
        Network network = EurostagTutorialExample1Factory.createWithFixedCurrentLimits();
        LimitViolation limitViolation = new LimitViolation(NHV1_NHV2_1, "NHV1_NHV2_1_name", LimitViolationType.CURRENT,
                limitName, acceptableDuration, limit, limitReduction, value, side);

        SubjectLimitViolationEntity subjectLimitViolationEntity = new SubjectLimitViolationEntity(NHV1_NHV2_1,
                "NHV1_NHV2_1_name");

        T limitViolationEntity = createLimitViolationEntity(network, limitViolation,
                subjectLimitViolationEntity);

        assertEquals(expectedNextLimitName, limitViolationEntity.getNextLimitName());
        assertEquals(expectedPatlLimit, limitViolationEntity.getPatlLimit());
        assertEquals(expectedAcceptableDuration, limitViolationEntity.getAcceptableDuration());
        assertEquals(expectedUpcomingAcceptableDuration, limitViolationEntity.getUpcomingAcceptableDuration());
        assertEquals(100 * limitViolation.getValue() / limitViolationEntity.getPatlLimit(),
                limitViolationEntity.getPatlLoading());
    }

    protected abstract T createLimitViolationEntity(Network network,
            LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolationEntity);
}
