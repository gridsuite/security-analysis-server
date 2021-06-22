/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import com.powsybl.commons.PowsyblException;
import com.powsybl.openloadflow.sa.OpenSecurityAnalysisFactory;
import com.rte_france.powsybl.hades2.Hades2SecurityAnalysisFactory;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisUtilTest {

    @Test
    public void test() {
        assertTrue(SecurityAnalysisUtil.getFactory("OpenLoadFlow") instanceof OpenSecurityAnalysisFactory);
        assertTrue(SecurityAnalysisUtil.getFactory("Hades2") instanceof Hades2SecurityAnalysisFactory);
        assertTrue(SecurityAnalysisUtil.getFactory(null) instanceof OpenSecurityAnalysisFactory);
        PowsyblException e = assertThrows(PowsyblException.class, () -> SecurityAnalysisUtil.getFactory("XXX"));
        assertEquals("Security analysis provider not found: XXX", e.getMessage());
    }
}
