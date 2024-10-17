/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import com.powsybl.commons.PowsyblException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@SpringBootTest
class SecurityAnalysisRunnerSupplierTest {

    @Value("${security-analysis.default-provider}")
    private String defaultSecurityAnalysisProvider;

    @Autowired
    private SecurityAnalysisRunnerSupplier securityAnalysisRunnerSupplier;

    @Test
    void test() {
        assertEquals("OpenLoadFlow", securityAnalysisRunnerSupplier.getRunner("OpenLoadFlow").getName());
        assertEquals("DynaFlow", securityAnalysisRunnerSupplier.getRunner("DynaFlow").getName());
        assertEquals(defaultSecurityAnalysisProvider, securityAnalysisRunnerSupplier.getRunner(null).getName());
        PowsyblException e = assertThrows(PowsyblException.class, () -> securityAnalysisRunnerSupplier.getRunner("XXX"));
        assertEquals("SecurityAnalysisProvider 'XXX' not found", e.getMessage());
    }
}
