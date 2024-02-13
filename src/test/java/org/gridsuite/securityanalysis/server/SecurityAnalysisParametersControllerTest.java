/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisParametersRepository;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.gridsuite.securityanalysis.server.util.MatcherJson;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService.getDefaultSecurityAnalysisParametersValues;
import static org.gridsuite.securityanalysis.server.util.SecurityAnalysisException.Type.PARAMETERS_NOT_FOUND;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Abdelsalem Hedhili <abdelsalem.hedhili at rte-france.com>
 */
@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
@SpringBootTest
@ContextConfigurationWithTestChannel
public class SecurityAnalysisParametersControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SecurityAnalysisParametersRepository securityAnalysisParametersRepository;

    @Value("${security-analysis.default-provider}")
    private String defaultProvider;

    private final SecurityAnalysisParametersValues defaultSecurityAnalysisParametersValues = getDefaultSecurityAnalysisParametersValues(defaultProvider);

    @Test
    public void securityAnalysisParametersCreateAndGetTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // create parameters
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .build();

        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters")
                        .content(objectMapper.writeValueAsString(securityAnalysisParametersValues1))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID createdParametersUuid = objectMapper.readValue(resultAsString, UUID.class);

        assertNotNull(createdParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(createdParametersUuid, 10, 11, 12, 13, 14);

        //get the created parameters
        mvcResult = mockMvc.perform(get("/" + VERSION + "/parameters/" + createdParametersUuid))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisParametersValues securityAnalysisParametersValues = objectMapper.readValue(resultAsString, SecurityAnalysisParametersValues.class);
        assertThat(securityAnalysisParametersValues1, new MatcherJson<>(objectMapper, securityAnalysisParametersValues));

        //get not existing parameters and expect 404
        mockMvc.perform(get("/" + VERSION + "/parameters/" + UUID.randomUUID()))
                .andExpect(status().isNotFound());
    }

    @Test
    public void securityAnalysisParametersUpdateTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        //update parameters with not existing ID and expect a 404
        mockMvc.perform(put("/" + VERSION + "/parameters/" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isNotFound(),
                        result -> assertTrue(result.getResponse().getContentAsString().contains(PARAMETERS_NOT_FOUND.name())));

        //create default parameters and return id
        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters/default"))
                .andExpect(
                        status().isOk()
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID createdParametersUuid = objectMapper.readValue(resultAsString, UUID.class);

        assertNotNull(createdParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(createdParametersUuid,
                defaultSecurityAnalysisParametersValues.getLowVoltageAbsoluteThreshold(),
                defaultSecurityAnalysisParametersValues.getLowVoltageProportionalThreshold(),
                defaultSecurityAnalysisParametersValues.getHighVoltageAbsoluteThreshold(),
                defaultSecurityAnalysisParametersValues.getHighVoltageProportionalThreshold(),
                defaultSecurityAnalysisParametersValues.getFlowProportionalThreshold());

        //update previous parameters
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .build();

        mvcResult = mockMvc.perform(put("/" + VERSION + "/parameters/" + createdParametersUuid)
                        .contentType(MediaType.APPLICATION_JSON).content(objectMapper.writeValueAsString(securityAnalysisParametersValues1)))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID updatedParametersUuid = objectMapper.readValue(resultAsString, UUID.class);
        assertEquals(createdParametersUuid, updatedParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(updatedParametersUuid, 10, 11, 12, 13, 14);

        //update previous parameters again but without giving the parameters values -> reset the parameters to default values
        mvcResult = mockMvc.perform(put("/" + VERSION + "/parameters/" + updatedParametersUuid))
                .andExpectAll(
                        status().isOk()
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        updatedParametersUuid = objectMapper.readValue(resultAsString, UUID.class);
        assertEquals(createdParametersUuid, updatedParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(updatedParametersUuid,
                defaultSecurityAnalysisParametersValues.getLowVoltageAbsoluteThreshold(),
                defaultSecurityAnalysisParametersValues.getLowVoltageProportionalThreshold(),
                defaultSecurityAnalysisParametersValues.getHighVoltageAbsoluteThreshold(),
                defaultSecurityAnalysisParametersValues.getHighVoltageProportionalThreshold(),
                defaultSecurityAnalysisParametersValues.getFlowProportionalThreshold());

        // update provider
        String newProvider = "newProvider";
        mvcResult = mockMvc.perform(patch("/" + VERSION + "/parameters/" + updatedParametersUuid + "/provider")
                .content(newProvider))
                .andExpect(status().isOk()).andReturn();
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(updatedParametersUuid).orElseThrow();
        assertEquals(newProvider, securityAnalysisParametersEntity.getProvider());

        // reset provider
        mvcResult = mockMvc.perform(patch("/" + VERSION + "/parameters/" + updatedParametersUuid + "/provider"))
                .andExpect(status().isOk()).andReturn();
        securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(updatedParametersUuid).orElseThrow();
        assertEquals(defaultProvider, securityAnalysisParametersEntity.getProvider());
    }

    @Test
    public void testDuplicateParameters() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // create parameters
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .build();

        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters")
                        .content(objectMapper.writeValueAsString(securityAnalysisParametersValues1))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID createdParametersUuid = objectMapper.readValue(resultAsString, UUID.class);

        assertNotNull(createdParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(createdParametersUuid, 10, 11, 12, 13, 14);

        //duplicate
        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters/" + createdParametersUuid))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID duplicatedParametersUuid = objectMapper.readValue(resultAsString, UUID.class);
        assertNotNull(duplicatedParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(duplicatedParametersUuid, 10, 11, 12, 13, 14);

        //duplicate not existing parameters and expect a 404
        mockMvc.perform(post("/" + VERSION + "/parameters/" + UUID.randomUUID()))
                .andExpectAll(
                        status().isNotFound()
                ).andReturn();
    }

    @Test
    public void testRemoveParameters() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // create parameters
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .build();

        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters")
                        .content(objectMapper.writeValueAsString(securityAnalysisParametersValues1))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID createdParametersUuid = objectMapper.readValue(resultAsString, UUID.class);

        assertNotNull(createdParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(createdParametersUuid, 10, 11, 12, 13, 14);

        //remove parameters
        mockMvc.perform(delete("/" + VERSION + "/parameters/" + createdParametersUuid))
                .andExpectAll(status().isOk());
        assertNull(securityAnalysisParametersRepository.findById(createdParametersUuid).orElse(null));
    }

    public void assertSecurityAnalysisParametersEntityAreEquals(UUID parametersUuid, double lowVoltageAbsoluteThreshold, double lowVoltageProportionalThreshold, double highVoltageAbsoluteThreshold, double highVoltageProportionalThreshold, double flowProportionalThreshold) {
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(parametersUuid).orElseThrow();
        assertEquals(lowVoltageAbsoluteThreshold, securityAnalysisParametersEntity.getLowVoltageAbsoluteThreshold(), 0.001);
        assertEquals(lowVoltageProportionalThreshold, securityAnalysisParametersEntity.getLowVoltageProportionalThreshold(), 0.001);
        assertEquals(highVoltageAbsoluteThreshold, securityAnalysisParametersEntity.getHighVoltageAbsoluteThreshold(), 0.001);
        assertEquals(highVoltageProportionalThreshold, securityAnalysisParametersEntity.getHighVoltageProportionalThreshold(), 0.001);
        assertEquals(flowProportionalThreshold, securityAnalysisParametersEntity.getFlowProportionalThreshold(), 0.001);
    }
}
