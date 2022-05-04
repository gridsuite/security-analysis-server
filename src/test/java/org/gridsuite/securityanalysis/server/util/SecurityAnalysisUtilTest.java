/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import com.powsybl.commons.PowsyblException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import static org.junit.Assert.*;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class SecurityAnalysisUtilTest {

    @Value("${loadflow.default-provider}")
    String defaultLoadflowProvider;

    @Autowired
    SecurityAnalysisRunnerSupplier securityAnalysisUtil;

    @Test
    public void test() {
        assertEquals("OpenSecurityAnalysis", securityAnalysisUtil.getRunner("OpenSecurityAnalysis").getName());
        assertEquals("Hades2", securityAnalysisUtil.getRunner("Hades2").getName());
        assertEquals(defaultLoadflowProvider, securityAnalysisUtil.getRunner(null).getName());
        PowsyblException e = assertThrows(PowsyblException.class, () -> securityAnalysisUtil.getRunner("XXX"));
        assertEquals("SecurityAnalysisProvider 'XXX' not found", e.getMessage());
    }
}
