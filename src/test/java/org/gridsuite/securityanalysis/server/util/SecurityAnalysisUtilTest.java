/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import com.powsybl.commons.PowsyblException;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisUtilTest {

    @Test
    public void test() {
        assertEquals(SecurityAnalysisUtil.getRunner("OpenSecurityAnalysis").getName(), "OpenSecurityAnalysis");
        assertEquals(SecurityAnalysisUtil.getRunner("Hades2").getName(), "Hades2");
        assertEquals(SecurityAnalysisUtil.getRunner(null).getName(), "OpenSecurityAnalysis");
        PowsyblException e = assertThrows(PowsyblException.class, () -> SecurityAnalysisUtil.getRunner("XXX"));
        assertEquals("SecurityAnalysisProvider 'XXX' not found", e.getMessage());
    }
}
