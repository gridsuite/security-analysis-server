/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.report.ReportNodeAdder;
import com.powsybl.commons.report.ReportNodeNoOp;
import com.powsybl.commons.report.TypedValue;
import com.powsybl.contingency.ContingencyElement;
import com.powsybl.iidm.network.Connectable;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import org.gridsuite.securityanalysis.server.computation.dto.ReportInfos;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.mockito.Mockito.*;


/**
 * @author Jamal KHEYYAD <jamal.kheyyad@rte-international.com>
 */
@SpringBootTest
public class SecurityAnalysisWorkerServiceTest {

    @Test
    public void testLogExcludedEquipment() {
        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        Connectable<?> connectable = network.getConnectable("NHV1_NHV2_1"); // get

        Assert.assertFalse(SecurityAnalysisWorkerService.isDisconnected(connectable));
        // disconnect the line
        connectable.disconnect();
        Assert.assertTrue(SecurityAnalysisWorkerService.isDisconnected(connectable));

        List<ContingencyElement> disconnectedEquipments = new ArrayList<>();
        disconnectedEquipments.add(ContingencyElement.of(connectable));
        UUID contingencyId = UUID.randomUUID();

        ReportNodeNoOp reportNodeNoOpMock = mock(ReportNodeNoOp.class);
        ReportNodeAdder childAdderMock = mock(ReportNodeAdder.class);
        // Configure the mock to return the mocked ChildAdder when newReportNode is called
        when(reportNodeNoOpMock.newReportNode()).thenReturn(childAdderMock);
        // configure reportNodeAdderMock
        when(childAdderMock.add()).thenReturn(reportNodeNoOpMock);
        when(childAdderMock.withMessageTemplate(anyString(), anyString())).thenReturn(childAdderMock);
        when(childAdderMock.withUntypedValue(anyString(), anyString())).thenReturn(childAdderMock);
        when(childAdderMock.withSeverity((TypedValue) any())).thenReturn(childAdderMock);

        SecurityAnalysisWorkerService.logDisconnectedEquipments(disconnectedEquipments, reportNodeNoOpMock, new ReportInfos(contingencyId, null, null));
        //verify that the childAdderMock.withMessageTemplate() is called
        verify(childAdderMock, times(2)).withMessageTemplate(anyString(), anyString());
        verify(childAdderMock, atLeastOnce()).withMessageTemplate(anyString(), ArgumentMatchers.contains("Disconnected"));
    }

}
