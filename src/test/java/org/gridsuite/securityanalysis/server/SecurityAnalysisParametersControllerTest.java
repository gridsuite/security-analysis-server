/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.gridsuite.computation.error.ComputationException;
import org.gridsuite.securityanalysis.server.dto.parameters.ContingencyListsInfos;
import org.gridsuite.securityanalysis.server.dto.parameters.IdNameInfos;
import org.gridsuite.securityanalysis.server.dto.parameters.LimitReductionsByVoltageLevel;
import org.gridsuite.securityanalysis.server.dto.parameters.SecurityAnalysisParametersValues;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisParametersEntity;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisParametersRepository;
import org.gridsuite.securityanalysis.server.service.DirectoryService;
import org.gridsuite.securityanalysis.server.service.LimitReductionService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisParametersService;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.gridsuite.securityanalysis.server.util.MatcherJson;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.computation.error.ComputationBusinessErrorCode.PARAMETERS_NOT_FOUND;
import static org.gridsuite.computation.service.NotificationService.HEADER_USER_ID;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Abdelsalem Hedhili <abdelsalem.hedhili at rte-france.com>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@AutoConfigureMockMvc
@SpringBootTest
@ContextConfigurationWithTestChannel
class SecurityAnalysisParametersControllerTest {

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

    @MockitoBean
    private DirectoryService directoryService;

    private static final String USER_ID = "userId";
    private static final UUID CONTINGENCY_LIST_ID = UUID.fromString("3f7c9e2a-8b41-4d6a-a1f3-9c5b72e8d4af");
    private static final String CONTINGENCY_LIST_NAME = "contingencyList";
    private static final UUID DEACTIVATED_CONTINGENCY_LIST_ID = UUID.fromString("b8a4f2c1-6d3e-4a9b-92f7-1e5c8d7a3b60");
    private static final String DEACTIVATED_CONTINGENCY_LIST_NAME = "deactivatedContingencyList";

    private List<ContingencyListsInfos> deactivatedContingencyListsInfos;
    private List<ContingencyListsInfos> contingencyListsInfos;

    @BeforeEach
    void setUp() {
        contingencyListsInfos = List.of(new ContingencyListsInfos(
                List.of(new IdNameInfos(CONTINGENCY_LIST_ID, CONTINGENCY_LIST_NAME)),
                "activated contingency lists",
                true));
        when(directoryService.getElementNames(List.of(CONTINGENCY_LIST_ID), USER_ID))
                .thenReturn(Map.of(CONTINGENCY_LIST_ID, CONTINGENCY_LIST_NAME));

        deactivatedContingencyListsInfos = List.of(new ContingencyListsInfos(
                List.of(new IdNameInfos(DEACTIVATED_CONTINGENCY_LIST_ID, DEACTIVATED_CONTINGENCY_LIST_NAME)),
                "deactivated contingency lists",
                false));
        when(directoryService.getElementNames(List.of(DEACTIVATED_CONTINGENCY_LIST_ID), USER_ID))
                .thenReturn(Map.of(DEACTIVATED_CONTINGENCY_LIST_ID, DEACTIVATED_CONTINGENCY_LIST_NAME));
    }

    @Test
    void limitReductionConfigTest() {
        List<LimitReductionsByVoltageLevel> limitReductions = limitReductionService.createDefaultLimitReductions();
        assertNotNull(limitReductions);
        assertFalse(limitReductions.isEmpty());

        List<LimitReductionsByVoltageLevel.VoltageLevel> vls = limitReductionService.getVoltageLevels();
        limitReductionService.setVoltageLevels(List.of());
        assertEquals("No configuration for voltage levels", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());
        limitReductionService.setVoltageLevels(vls);

        List<LimitReductionsByVoltageLevel.LimitDuration> lrs = limitReductionService.getLimitDurations();
        limitReductionService.setLimitDurations(List.of());
        assertEquals("No configuration for limit durations", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());
        limitReductionService.setLimitDurations(lrs);

        limitReductionService.setDefaultValues(List.of());
        assertEquals("No values provided", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of()));
        assertEquals("No values provided", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0)));
        assertEquals("Not enough values provided for voltage levels", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0), List.of(1.0), List.of(1.0)));
        assertEquals("Too many values provided for voltage levels", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0), List.of(1.0)));
        assertEquals("Not enough values provided for limit durations", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0, 1.0, 1.0, 1.0, 1.0), List.of(1.0)));
        assertEquals("Number of values for a voltage level is incorrect", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(1.0, 1.0, 1.0, 1.0, 1.0), List.of(1.0, 1.0, 1.0, 1.0, 1.0)));
        assertEquals("Too many values provided for limit durations", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());

        limitReductionService.setDefaultValues(List.of(List.of(2.0, 1.0, 1.0, 1.0), List.of(1.0, 1.0, 1.0, 1.0)));
        assertEquals("Value not between 0 and 1", assertThrows(ComputationException.class, () -> limitReductionService.createDefaultLimitReductions()).getMessage());
    }

    @Test
    void securityAnalysisParametersCreateAndGetTest() throws Exception {
        // Create parameters
        List<List<Double>> limitReductions = List.of(List.of(1.0, 0.9, 0.8, 0.7), List.of(1.0, 0.9, 0.8, 0.7));
        SecurityAnalysisParametersValues.SecurityAnalysisParametersValuesBuilder builder = SecurityAnalysisParametersValues.builder()
                .lowVoltageAbsoluteThreshold(10)
                .lowVoltageProportionalThreshold(11)
                .highVoltageAbsoluteThreshold(12)
                .highVoltageProportionalThreshold(13)
                .flowProportionalThreshold(14);

        // Get no limits with no provider
        testParametersCreateAndGetTest(builder.build());

        // Get no limits with a provider other than 'OpenLoadFlow'
        testParametersCreateAndGetTest(builder.provider("provider").build());
        testParametersCreateAndGetTest(builder
                .provider("provider")
                .limitReductions(limitReductionService.createLimitReductions(limitReductions))
                .build(), builder.provider("provider").limitReductions(null).build());

        // Get default limits with 'OpenLoadFlow' provider
        String provider = "OpenLoadFlow";
        testParametersCreateAndGetTest(builder.provider(provider).limitReductions(null).build(), builder
                .provider(provider)
                .limitReductions(limitReductionService.createDefaultLimitReductions())
                .build());

        // Get limits with 'OpenLoadFlow' provider
        testParametersCreateAndGetTest(builder
                .provider(provider)
                .limitReductions(limitReductionService.createLimitReductions(limitReductions))
                .build());

        // Get with deactivated contingency lists
        SQLStatementCountValidator.reset();
        testParametersCreateAndGetTest(builder.contingencyListsInfos(deactivatedContingencyListsInfos).build());
        /*
        insert
            security_analysis_parameters
            parameters_contingency_lists
            limit_reduction_entity
            limit_reduction_entity_reductions
            parameters_contingency_lists_contingency_list
        update
            parameters_contingency_lists
            limit_reduction_entity
         */
        assertRequestsCount(5, 5, 2, 0);

        // Get with contingency lists
        SQLStatementCountValidator.reset();
        testParametersCreateAndGetTest(builder.contingencyListsInfos(contingencyListsInfos).build());
        /*
        insert
            security_analysis_parameters
            parameters_contingency_lists
            limit_reduction_entity
            limit_reduction_entity_reductions
            parameters_contingency_lists_contingency_list
        update
            parameters_contingency_lists
            limit_reduction_entity
         */
        assertRequestsCount(5, 5, 2, 0);

        // Get not existing parameters and expect 404
        mockMvc.perform(get("/" + VERSION + "/parameters/" + UUID.randomUUID())
                        .header(HEADER_USER_ID, USER_ID))
                .andExpect(status().isNotFound());
    }

    private void testParametersCreateAndGetTest(SecurityAnalysisParametersValues parametersToCreate) throws Exception {
        testParametersCreateAndGetTest(parametersToCreate, parametersToCreate);
    }

    private void testParametersCreateAndGetTest(SecurityAnalysisParametersValues parametersToCreate, SecurityAnalysisParametersValues parametersExpected) throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters")
                        .header(HEADER_USER_ID, USER_ID)
                        .content(objectMapper.writeValueAsString(parametersToCreate))
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        UUID createdParametersUuid = objectMapper.readValue(mvcResult.getResponse().getContentAsString(), UUID.class);

        assertNotNull(createdParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(createdParametersUuid, 10, 11, 12, 13, 14);

        // Get the created parameters
        mvcResult = mockMvc.perform(get("/" + VERSION + "/parameters/" + createdParametersUuid)
                        .header(HEADER_USER_ID, USER_ID))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        assertThat(objectMapper.readValue(mvcResult.getResponse().getContentAsString(), SecurityAnalysisParametersValues.class), new MatcherJson<>(objectMapper, parametersExpected));
    }

    @Test
    void securityAnalysisParametersUpdateTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        //update parameters with not existing ID and expect a 404
        mockMvc.perform(put("/" + VERSION + "/parameters/" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isNotFound(),
                        result -> assertTrue(result.getResponse().getContentAsString().contains(PARAMETERS_NOT_FOUND.value())));

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
                .contingencyListsInfos(contingencyListsInfos)
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
        mockMvc.perform(put("/" + VERSION + "/parameters/" + updatedParametersUuid + "/provider")
                .content(newProvider))
                .andExpect(status().isOk()).andReturn();
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(updatedParametersUuid).orElseThrow();
        assertEquals(newProvider, securityAnalysisParametersEntity.getProvider());

        // reset provider
        mockMvc.perform(put("/" + VERSION + "/parameters/" + updatedParametersUuid + "/provider"))
                .andExpect(status().isOk()).andReturn();
        securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(updatedParametersUuid).orElseThrow();
        assertEquals(defaultProvider, securityAnalysisParametersEntity.getProvider());
    }

    @Test
    void testDuplicateParameters() throws Exception {
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
                .contingencyListsInfos(contingencyListsInfos)
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
        mvcResult = mockMvc.perform(post("/" + VERSION + "/parameters").queryParam("duplicateFrom", createdParametersUuid.toString())
                        .header(HEADER_USER_ID, USER_ID))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID duplicatedParametersUuid = objectMapper.readValue(resultAsString, UUID.class);
        assertNotNull(duplicatedParametersUuid);
        assertSecurityAnalysisParametersEntityAreEquals(duplicatedParametersUuid, 10, 11, 12, 13, 14);

        //duplicate not existing parameters and expect a 404
        mockMvc.perform(post("/" + VERSION + "/parameters")
                        .header(HEADER_USER_ID, USER_ID)
                        .queryParam("duplicateFrom", UUID.randomUUID().toString()))
                .andExpectAll(
                        status().isNotFound()
                ).andReturn();
    }

    @Test
    void testRemoveParameters() throws Exception {
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
                .contingencyListsInfos(contingencyListsInfos)
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

    @Test
    void testGetDefaultLimitReductions() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/v1/parameters/default-limit-reductions")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        String responseContent = mvcResult.getResponse().getContentAsString();
        List<LimitReductionsByVoltageLevel> limitReductions = objectMapper.readValue(responseContent, new TypeReference<>() { });

        assertNotNull(limitReductions);
        assertFalse(limitReductions.isEmpty());
    }

    private void assertSecurityAnalysisParametersEntityAreEquals(UUID parametersUuid, double lowVoltageAbsoluteThreshold, double lowVoltageProportionalThreshold, double highVoltageAbsoluteThreshold, double highVoltageProportionalThreshold, double flowProportionalThreshold) {
        SecurityAnalysisParametersEntity securityAnalysisParametersEntity = securityAnalysisParametersRepository.findById(parametersUuid).orElseThrow();
        assertEquals(lowVoltageAbsoluteThreshold, securityAnalysisParametersEntity.getLowVoltageAbsoluteThreshold(), 0.001);
        assertEquals(lowVoltageProportionalThreshold, securityAnalysisParametersEntity.getLowVoltageProportionalThreshold(), 0.001);
        assertEquals(highVoltageAbsoluteThreshold, securityAnalysisParametersEntity.getHighVoltageAbsoluteThreshold(), 0.001);
        assertEquals(highVoltageProportionalThreshold, securityAnalysisParametersEntity.getHighVoltageProportionalThreshold(), 0.001);
        assertEquals(flowProportionalThreshold, securityAnalysisParametersEntity.getFlowProportionalThreshold(), 0.001);
    }
}
