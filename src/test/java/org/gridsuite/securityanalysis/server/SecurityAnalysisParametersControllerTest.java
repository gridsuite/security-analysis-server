/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.gridsuite.securityanalysis.server.dto.LimitReductionsByVoltageLevel;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisParametersRepository;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.gridsuite.securityanalysis.server.service.LimitReductionService;
import org.gridsuite.securityanalysis.server.util.MatcherJson;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
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

import java.util.List;
import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
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

    @Autowired
    private SecurityAnalysisParametersService securityAnalysisParametersService;

    @Autowired
    private LimitReductionService limitReductionService;

    @Test
    public void limitReductionConfigTest() {
        List<LimitReductionsByVoltageLevel> limitReductions = limitReductionService.createDefaultLimitReductions();
        assertNotNull(limitReductions);
        assertFalse(limitReductions.isEmpty());

        List<LimitReductionsByVoltageLevel.VoltageLevel> vls = limitReductionService.getVoltageLevels();
        limitReductionService.setVoltageLevels(List.of());
        assertEquals("No configuration for voltage levels", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());
        limitReductionService.setVoltageLevels(vls);

        List<LimitReductionsByVoltageLevel.LimitDuration> lrs = limitReductionService.getLimitDurations();
        limitReductionService.setLimitDurations(List.of());
        assertEquals("No configuration for limit durations", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());
        limitReductionService.setLimitDurations(lrs);

        limitReductionService.setDefaultValues(List.of());
        assertEquals("No values provided", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of()));
        assertEquals("No values provided", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0)));
        assertEquals("Not enough values provided for voltage levels", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0), List.of(1.0), List.of(1.0)));
        assertEquals("Too many values provided for voltage levels", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0), List.of(1.0)));
        assertEquals("Not enough values provided for limit durations", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0, 1.0, 1.0, 1.0, 1.0), List.of(1.0)));
        assertEquals("Number of values for a voltage level is incorrect", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0, 1.0, 1.0, 1.0, 1.0), List.of(1.0, 1.0, 1.0, 1.0, 1.0)));
        assertEquals("Too many values provided for limit durations", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(2.0, 1.0, 1.0, 1.0), List.of(1.0, 1.0, 1.0, 1.0)));
        assertEquals("Value not between 0 and 1", assertThrows(SecurityAnalysisException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());
    }

    @Test
    public void securityAnalysisParametersCreateAndGetTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // create parameters
        List<List<Double>> limitReductions = List.of(List.of(1.0, 0.9, 0.8, 0.7), List.of(1.0, 0.9, 0.8, 0.7));
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .limitReductions(limitReductionService.createLimitReductions(limitReductions))
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

        SecurityAnalysisParametersValues defaultSecurityAnalysisParametersValues = securityAnalysisParametersService.getDefaultSecurityAnalysisParametersValues(defaultProvider);

        assertSecurityAnalysisParametersEntityAreEquals(createdParametersUuid,
                defaultSecurityAnalysisParametersValues.getLowVoltageAbsoluteThreshold(),
                defaultSecurityAnalysisParametersValues.getLowVoltageProportionalThreshold(),
                defaultSecurityAnalysisParametersValues.getHighVoltageAbsoluteThreshold(),
                defaultSecurityAnalysisParametersValues.getHighVoltageProportionalThreshold(),
                defaultSecurityAnalysisParametersValues.getFlowProportionalThreshold());

        //update previous parameters
        List<List<Double>> limitReductions = List.of(List.of(0.2, 0.6, 0.5, 0.7), List.of(0.2, 0.6, 0.5, 0.7));
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .limitReductions(limitReductionService.createLimitReductions(limitReductions))
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
        mockMvc.perform(patch("/" + VERSION + "/parameters/" + updatedParametersUuid + "/provider")
                .content(newProvider))
                .andExpect(status().isOk()).andReturn();
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(updatedParametersUuid).orElseThrow();
        assertEquals(newProvider, securityAnalysisParametersEntity.getProvider());

        // reset provider
        mockMvc.perform(patch("/" + VERSION + "/parameters/" + updatedParametersUuid + "/provider"))
                .andExpect(status().isOk()).andReturn();
        securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(updatedParametersUuid).orElseThrow();
        assertEquals(defaultProvider, securityAnalysisParametersEntity.getProvider());
    }

    @Test
    public void testDuplicateParameters() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // create parameters
        List<List<Double>> limitReductions = List.of(List.of(1.0, 0.9, 0.8, 0.7), List.of(1.0, 0.9, 0.8, 0.7));
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .limitReductions(limitReductionService.createLimitReductions(limitReductions))
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
        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters").queryParam("duplicateFrom", createdParametersUuid.toString()))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID duplicatedParametersUuid = objectMapper.readValue(resultAsString, UUID.class);
        assertNotNull(duplicatedParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(duplicatedParametersUuid, 10, 11, 12, 13, 14);

        //duplicate not existing parameters and expect a 404
        mockMvc.perform(post("/" + VERSION + "/parameters").queryParam("duplicateFrom", UUID.randomUUID().toString()))
                .andExpectAll(
                        status().isNotFound()
                ).andReturn();
    }

    @Test
    public void testRemoveParameters() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // create parameters
        List<List<Double>> limitReductions = List.of(List.of(1.0, 0.9, 0.8, 0.7), List.of(1.0, 0.9, 0.8, 0.7));
        SecurityAnalysisParametersValues securityAnalysisParametersValues1 = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14)
                .limitReductions(limitReductionService.createLimitReductions(limitReductions))
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
