/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.report.ReportNodeNoOp;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.iidm.network.Connectable;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import org.gridsuite.securityanalysis.server.computation.dto.ReportInfos;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;


/**
 * @author Jamal KHEYYAD <jamal.kheyyad@rte-international.com>
 */
@SpringBootTest
public class SecurityAnalysisWorkerServiceTest {
    static final String VARIANT_1_ID = "variant_1";

    @Test
    public void testIsDisconnected() {
        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_1_ID);
        Connectable<?> connectable = network.getConnectable("NHV1_NHV2_1"); // get

        Assert.assertFalse(SecurityAnalysisWorkerService.isDisconnected(connectable));
        // disconnect the line
        connectable.disconnect();
        Assert.assertTrue(SecurityAnalysisWorkerService.isDisconnected(connectable));

        List<ContingencyElement> disconnectedEquipments = new ArrayList<>();
        disconnectedEquipments.add(ContingencyElement.of(connectable));
        UUID contingencyId = UUID.randomUUID();
        SecurityAnalysisWorkerService.logDisconnectedEquipments(disconnectedEquipments, new ReportNodeNoOp(), new ReportInfos(contingencyId, null, null));
    }

}
