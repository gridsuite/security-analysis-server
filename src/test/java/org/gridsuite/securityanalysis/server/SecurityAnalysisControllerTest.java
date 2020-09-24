/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.MockSecurityAnalysisFactory.CONTINGENCY_LIST_NAME;
import static org.mockito.BDDMockito.given;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RunWith(SpringRunner.class)
@WebMvcTest(SecurityAnalysisController.class)
@ContextConfiguration(classes = {SecurityAnalysisApplication.class})
@ActiveProfiles("test")
public class SecurityAnalysisControllerTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID OTHER_NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e5");

    private static final String EXPECTED_JSON = "{\"version\":\"1.0\",\"preContingencyResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]},\"postContingencyResults\":[{\"contingency\":{\"id\":\"l1\",\"elements\":[{\"id\":\"l1\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]}},{\"contingency\":{\"id\":\"l2\",\"elements\":[{\"id\":\"l2\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]}}]}";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private SecurityAnalysisService securityAnalysisService;

    @MockBean
    private NetworkStoreService networkStoreService;

    @MockBean
    private ActionsService actionsService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        Network network = EurostagTutorialExample1Factory.create();
        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(network);

        Network otherNetwork = Network.create("other", "test");
        given(networkStoreService.getNetwork(OTHER_NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(otherNetwork);

        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID))
                .willReturn(MockSecurityAnalysisFactory.CONTINGENCIES);
    }

    @Test
    public void test() throws Exception {
        mvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME)
                .contentType(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(content().json(EXPECTED_JSON));
    }

    @Test
    public void testWithMergingView() throws Exception {
        mvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME + "&networkUuid=" + OTHER_NETWORK_UUID)
                .contentType(APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(APPLICATION_JSON))
                .andExpect(content().json(EXPECTED_JSON));
    }
}
