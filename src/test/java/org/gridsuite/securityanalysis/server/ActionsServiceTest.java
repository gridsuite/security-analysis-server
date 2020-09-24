/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RunWith(MockitoJUnitRunner.class)
public class ActionsServiceTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");

    private static final String LIST_NAME = "myList";

    private static final Contingency CONTINGENCY = new Contingency("c1", new BranchContingency("b1"));

    @Mock
    private RestTemplate restTemplate;

    private ActionsService actionsService;

    @Before
    public void setUp() {
        actionsService = new ActionsService(restTemplate);
    }

    @Test
    public void test() {
        when(restTemplate.exchange(anyString(),
                                   eq(HttpMethod.GET),
                                   isNull(),
                                   eq(new ParameterizedTypeReference<List<Contingency>>() { }),
                                   eq(LIST_NAME),
                                   eq(NETWORK_UUID.toString())))
                .thenReturn(ResponseEntity.ok(List.of(CONTINGENCY)));
        List<Contingency> list = actionsService.getContingencyList(LIST_NAME, NETWORK_UUID);
        assertEquals(List.of(CONTINGENCY), list);
    }
}
