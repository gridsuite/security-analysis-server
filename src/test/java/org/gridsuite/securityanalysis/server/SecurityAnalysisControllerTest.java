/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.powsybl.commons.report.ReportNode;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.loadflow.LoadFlowParameters;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.*;
import com.powsybl.ws.commons.computation.service.ReportService;
import com.powsybl.ws.commons.computation.service.UuidGeneratorService;
import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.assertj.core.api.Assertions;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.gridsuite.securityanalysis.server.repositories.SubjectLimitViolationRepository;
import org.gridsuite.securityanalysis.server.repositories.specifications.SpecificationUtils;
import org.gridsuite.securityanalysis.server.service.ActionsService;
import org.gridsuite.securityanalysis.server.service.LoadFlowService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;
import org.gridsuite.securityanalysis.server.util.MatcherJson;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.stream.binder.test.OutputDestination;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.messaging.Message;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static com.powsybl.ws.commons.computation.service.NotificationService.*;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisService.COMPUTATION_TYPE;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;
import static org.gridsuite.securityanalysis.server.util.TestUtils.assertLogMessage;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.http.MediaType.APPLICATION_OCTET_STREAM_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */

@AutoConfigureMockMvc
@SpringBootTest
@ContextConfigurationWithTestChannel
class SecurityAnalysisControllerTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID NETWORK_STOP_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e6");
    private static final UUID RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5d");
    private static final UUID REPORT_UUID = UUID.fromString("0c4de370-3e6a-4d72-b292-d355a97e0d53");
    private static final UUID OTHER_RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5a");

    private static final int TIMEOUT = 1000;

    private static final String ERROR_MESSAGE = "Error message test";

    @Autowired
    private OutputDestination output;

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private NetworkStoreService networkStoreService;

    @MockBean
    private ActionsService actionsService;

    @MockBean
    private ReportService reportService;

    @Autowired
    private LoadFlowService loadFlowService;

    @MockBean
    private UuidGeneratorService uuidGeneratorService;

    @Autowired
    private SecurityAnalysisWorkerService workerService;

    @Autowired
    private ObjectMapper mapper;

    @Autowired
    private SubjectLimitViolationRepository subjectLimitViolationRepository;

    private static final Map<String, String> ENUM_TRANSLATIONS_EN = Map.of(
        "ONE", "Side 1",
        "TWO", "Side 2",
        "CURRENT", "Current",
        "HIGH_VOLTAGE", "High voltage",
        "FAILED", "Failed",
        "CONVERGED", "Converged",
        "permanent", "IST"
    );

    private static final Map<String, String> ENUM_TRANSLATIONS_FR = Map.of(
        "ONE", "Côté 1",
        "TWO", "Côté 2",
        "CURRENT", "Intensité",
        "HIGH_VOLTAGE", "Tension haute",
        "FAILED", "Echec",
        "CONVERGED", "Convergence",
        "permanent", "IST"
    );

    @BeforeEach
    void setUp() throws Exception {
        WireMockServer wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();

        MockitoAnnotations.initMocks(this);

        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_1_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_2_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_3_ID);

        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.ALL_COLLECTIONS_NEEDED_FOR_BUS_VIEW)).willReturn(network);

        when(networkStoreService.getNetwork(NETWORK_STOP_UUID, PreloadingStrategy.ALL_COLLECTIONS_NEEDED_FOR_BUS_VIEW)).thenAnswer(invocation -> {
            //Needed so the stop call doesn't arrive too late
            Network network1 = new NetworkFactoryImpl().createNetwork("other", "test");
            network1.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_TO_STOP_ID);
            return network1;
        });

        // UUID service mocking to always generate the same result UUID
        given(uuidGeneratorService.generate()).willReturn(RESULT_UUID);

        doNothing().when(reportService).sendReport(any(UUID.class), any(ReportNode.class));

        // SecurityAnalysis.Runner constructor is private..
        Constructor<SecurityAnalysis.Runner> constructor = SecurityAnalysis.Runner.class.getDeclaredConstructor(SecurityAnalysisProvider.class);
        constructor.setAccessible(true);
        SecurityAnalysis.Runner runner = constructor.newInstance(new SecurityAnalysisProviderMock());
        // mock the powsybl security analysis
        workerService.setSecurityAnalysisFactorySupplier(provider -> runner);

        // mock loadFlow parameters
        loadFlowService.setLoadFlowServiceBaseUri(wireMockServer.baseUrl());
        LoadFlowParametersValues loadFlowParametersValues = LoadFlowParametersValues.builder()
            .commonParameters(LoadFlowParameters.load())
            .specificParameters(Map.of("reactiveRangeCheckMode", "TARGET_P", "plausibleActivePowerLimit", "5000.0"))
            .build();
        wireMockServer.stubFor(WireMock.get(WireMock.urlMatching("/v1/parameters/.*/values\\?provider=.*"))
            .willReturn(WireMock.ok().withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE).withBody(mapper.writeValueAsString(loadFlowParametersValues))));

        // purge messages
        while (output.receive(1000, "sa.result") != null) {
        }
        // purge messages
        while (output.receive(1000, "sa.run") != null) {
        }
        while (output.receive(1000, "sa.cancel") != null) {
        }
        while (output.receive(1000, "sa.stopped") != null) {
        }
        while (output.receive(1000, "sa.failed") != null) {
        }
    }

    // added for testStatus can return null, after runTest
    @AfterEach
    void tearDown() throws Exception {
        mockMvc.perform(delete("/" + VERSION + "/results"))
                .andExpect(status().isOk());
    }

    private void simpleRunRequest(SecurityAnalysisParametersInfos lfParams) throws Exception {
        MvcResult mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID + "&loadFlowParametersUuid=" + UUID.randomUUID())
                .contentType(MediaType.APPLICATION_JSON)
                .header(HEADER_USER_ID, "testUserId")
                .content(mapper.writeValueAsString(lfParams)))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)).andReturn();
        String resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);

        assertThat(RESULT_VARIANT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    void runTestWithLFParams() throws Exception {
        // run with some empty params
        simpleRunRequest(SecurityAnalysisParametersInfos.builder().build());
        // with default LFParams
        simpleRunRequest(SecurityAnalysisParametersInfos.builder()
                .parameters(SecurityAnalysisParameters.load())
                .build());
        // with 2 specific LFParams
        simpleRunRequest(SecurityAnalysisParametersInfos.builder()
                .parameters(SecurityAnalysisParameters.load())
                .loadFlowSpecificParameters(Map.of("reactiveRangeCheckMode", "TARGET_P", "plausibleActivePowerLimit", "4000.0"))
                .build());
    }

    @Test
    void runTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // run with specific variant
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID + "&provider=OpenLoadFlow" + "&loadFlowParametersUuid=" + UUID.randomUUID())
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT_VARIANT, new MatcherJson<>(mapper, securityAnalysisResult));

        // run with implicit initial variant
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME + "&loadFlowParametersUuid=" + UUID.randomUUID())
           .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
           .andExpectAll(
               status().isOk(),
               content().contentType(MediaType.APPLICATION_JSON)
           ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    void runAndSaveTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        SQLStatementCountValidator.reset();
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
            + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow" + "&loadFlowParametersUuid=" + UUID.randomUUID())
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();
        // * inserts
        // security_analysis_result
        // contingency
        // contingency_limit_violation
        // pre_contingency_limit_violation
        // subject_limit_violation
        // contingency_entity_contingency_elements

        // * updates
        // contingency_limit_violation
        // pre_contingency_limit_violation
        // security_analysis_result
        // TODO remove those useless updates if everything is well done !
        assertRequestsCount(2, 6, 3, 0);

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        Message<byte[]> resultMessage = output.receive(TIMEOUT, "sa.result");
        assertEquals(RESULT_UUID.toString(), resultMessage.getHeaders().get("resultUuid"));
        assertEquals("me", resultMessage.getHeaders().get("receiver"));

        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/n-result"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON));

        assertFiltredResultN();
        checkNResultEnumFilters(RESULT_UUID);

        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-contingencies-result/paged"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON));

        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-constraints-result/paged"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON));

        checkNmKResultEnumFilters(RESULT_UUID);

        // should throw not found if result does not exist
        assertResultNotFound(OTHER_RESULT_UUID);

        // test one result deletion
        mockMvc.perform(delete("/" + VERSION + "/results").queryParam("resultsUuids", RESULT_UUID.toString()))
                .andExpect(status().isOk());

        assertResultNotFound(RESULT_UUID);
    }

    @Test
    void testDeterministicResults() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        SQLStatementCountValidator.reset();
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow" + "&loadFlowParametersUuid=" + UUID.randomUUID())
                        .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        content().contentType(MediaType.APPLICATION_JSON),
                        status().isOk()
                ).andReturn();

        assertRequestsCount(2, 6, 3, 0);

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        Message<byte[]> resultMessage = output.receive(TIMEOUT, "sa.result");
        assertEquals(RESULT_UUID.toString(), resultMessage.getHeaders().get("resultUuid"));
        assertEquals("me", resultMessage.getHeaders().get("receiver"));

        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/n-result"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON));

        assertFiltredResultN();

        var res = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-constraints-result/paged"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString();

        JsonNode resultsPageNode0 = mapper.readTree(res);
        ObjectReader faultResultsReader = mapper.readerFor(new TypeReference<List<SubjectLimitViolationResultDTO>>() { });
        List<SubjectLimitViolationResultDTO> subjectLimitViolationResultDTOS = faultResultsReader.readValue(resultsPageNode0.get("content"));
        List<String> result = subjectLimitViolationResultDTOS.stream().map(SubjectLimitViolationResultDTO::getSubjectId).toList();
        List<String> expectedResultInOrder = subjectLimitViolationRepository.findAll().stream().sorted(Comparator.comparing(o -> o.getId().toString())).map(SubjectLimitViolationEntity::getSubjectId).toList();
        assertEquals(expectedResultInOrder, result);

        //test with a sorted paged request
        res = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-constraints-result/paged")
                        .param("page", "0")
                        .param("size", "10")
                        .param("sort", "subjectId"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON))
                .andReturn().getResponse().getContentAsString();

        resultsPageNode0 = mapper.readTree(res);
        faultResultsReader = mapper.readerFor(new TypeReference<List<SubjectLimitViolationResultDTO>>() { });
        subjectLimitViolationResultDTOS = faultResultsReader.readValue(resultsPageNode0.get("content"));
        result = subjectLimitViolationResultDTOS.stream().map(SubjectLimitViolationResultDTO::getSubjectId).toList();
        expectedResultInOrder = subjectLimitViolationRepository.findAll().stream().sorted(Comparator.comparing(SubjectLimitViolationEntity::getSubjectId).thenComparing(SubjectLimitViolationEntity::getId)).map(SubjectLimitViolationEntity::getSubjectId).toList();
        assertEquals(expectedResultInOrder, result);
    }

    private static String buildFilterUrl() throws JsonProcessingException {
        List<ResourceFilterDTO> filters = List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "vl1", AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
            new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, new String[]{"HIGH_VOLTAGE"}, AbstractLimitViolationEntity.Fields.limitType),
            new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.GREATER_THAN_OR_EQUAL, "399", AbstractLimitViolationEntity.Fields.limit),
            new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.LESS_THAN_OR_EQUAL, "420", AbstractLimitViolationEntity.Fields.value),
            new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.NOT_EQUAL, "2", AbstractLimitViolationEntity.Fields.acceptableDuration)
        );
        String jsonFilters = new ObjectMapper().writeValueAsString(filters);
        return "filters=" + URLEncoder.encode(jsonFilters, StandardCharsets.UTF_8);
    }

    private void assertFiltredResultN() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/n-result?" + buildFilterUrl()))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();
        String resultAsString = mvcResult.getResponse().getContentAsString();
        List<PreContingencyLimitViolationResultDTO> preContingencyResult = mapper.readValue(resultAsString, new TypeReference<>() { });
        assertEquals(1, preContingencyResult.size());
    }

    private void checkNResultEnumFilters(UUID resultUuid) throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/n-result"))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)).andReturn();

        List<PreContingencyLimitViolationResultDTO> nResults = mapper.readValue(mvcResult.getResponse().getContentAsString(), new TypeReference<>() { });

        List<LimitViolationType> expectedLimitTypes = nResults.stream().map(result -> result.getLimitViolation().getLimitType()).distinct().toList();
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/{resultUuid}/n-limit-types", resultUuid))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();
        List<LimitViolationType> limitTypes = mapper.readValue(mvcResult.getResponse().getContentAsString(), new TypeReference<>() { });
        Assertions.assertThat(limitTypes).hasSameElementsAs(expectedLimitTypes);

        List<ThreeSides> expectedSides = nResults.stream().map(result -> result.getLimitViolation().getSide()).distinct().filter(side -> side != null).toList();
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/{resultUuid}/n-branch-sides", resultUuid))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();
        List<ThreeSides> sides = mapper.readValue(mvcResult.getResponse().getContentAsString(), new TypeReference<>() { });
        Assertions.assertThat(sides).hasSameElementsAs(expectedSides);
    }

    private void checkNmKResultEnumFilters(UUID resultUuid) throws Exception {
        // getting 100 elements here because we want to fetch all test datas to check fetched filters belongs to fetched results
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-contingencies-result/paged?size=100"))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)).andReturn();
        // getting paged result as list
        JsonNode resultsJsonNode = mapper.readTree(mvcResult.getResponse().getContentAsString());
        ObjectReader resultsObjectReader = mapper.readerFor(new TypeReference<List<ContingencyResultDTO>>() { });
        List<ContingencyResultDTO> nmkResult = resultsObjectReader.readValue(resultsJsonNode.get("content"));

        List<LimitViolationType> expectedLimitTypes = nmkResult.stream().map(ContingencyResultDTO::getSubjectLimitViolations).flatMap(subjectLimitViolationDTOS -> subjectLimitViolationDTOS.stream().map(slm -> slm.getLimitViolation().getLimitType())).distinct().toList();
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/{resultUuid}/nmk-limit-types", resultUuid))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();
        List<LimitViolationType> limitTypes = mapper.readValue(mvcResult.getResponse().getContentAsString(), new TypeReference<>() { });
        Assertions.assertThat(limitTypes).hasSameElementsAs(expectedLimitTypes);

        List<ThreeSides> expectedSides = nmkResult.stream().map(ContingencyResultDTO::getSubjectLimitViolations).flatMap(subjectLimitViolationDTOS -> subjectLimitViolationDTOS.stream().map(slm -> slm.getLimitViolation().getSide())).filter(Objects::nonNull).distinct().toList();
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/{resultUuid}/nmk-branch-sides", resultUuid))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();
        List<ThreeSides> sides = mapper.readValue(mvcResult.getResponse().getContentAsString(), new TypeReference<>() { });
        Assertions.assertThat(sides).hasSameElementsAs(expectedSides);

        List<LoadFlowResult.ComponentResult.Status> expectedStatus = nmkResult.stream().map(result -> LoadFlowResult.ComponentResult.Status.valueOf(result.getContingency().getStatus())).distinct().toList();
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/{resultUuid}/nmk-computation-status", resultUuid))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();
        List<LoadFlowResult.ComponentResult.Status> status = mapper.readValue(mvcResult.getResponse().getContentAsString(), new TypeReference<>() { });
        Assertions.assertThat(status).hasSameElementsAs(expectedStatus);
    }

    @Test
    void runWithTwoLists() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME +
            "&contingencyListName=" + CONTINGENCY_LIST2_NAME + "&variantId=" + VARIANT_1_ID + "&loadFlowParametersUuid=" + UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                .header(HEADER_USER_ID, "testUserId"))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();
        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    void deleteResultsTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME + "&loadFlowParametersUuid=" + UUID.randomUUID())
            .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        output.receive(TIMEOUT, "sa.result");

        mockMvc.perform(delete("/" + VERSION + "/results"))
                .andExpect(status().isOk());

        assertResultNotFound(RESULT_UUID);
    }

    @Test
    void testStatus() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        // getting status when result does not exist
        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/status"))
            .andExpectAll(
                status().isOk(),
                content().string("")
            );

        // invalidating unexisting result
        mockMvc.perform(put("/" + VERSION + "/results/invalidate-status?resultUuid=" + RESULT_UUID))
                .andExpect(status().isOk());

        // checking status is updated anyway
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/status"))
            .andExpect(status().isOk()).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisStatus securityAnalysisStatus = mapper.readValue(resultAsString, SecurityAnalysisStatus.class);
        assertEquals(SecurityAnalysisStatus.NOT_DONE, securityAnalysisStatus);

        // running computation to create result
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
            + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow" + "&loadFlowParametersUuid=" + UUID.randomUUID())
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        Message<byte[]> resultMessage = output.receive(TIMEOUT, "sa.result");
        assertEquals(RESULT_UUID.toString(), resultMessage.getHeaders().get("resultUuid"));
        assertEquals("me", resultMessage.getHeaders().get("receiver"));

        // getting status of this result
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/status"))
            .andExpect(status().isOk()).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        securityAnalysisStatus = mapper.readValue(resultAsString, SecurityAnalysisStatus.class);
        assertEquals(SecurityAnalysisStatus.CONVERGED, securityAnalysisStatus);

        // invalidating existing result
        mockMvc.perform(put("/" + VERSION + "/results/invalidate-status?resultUuid=" + RESULT_UUID))
            .andExpect(status().isOk());

        // checking invalidated status
        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/status"))
            .andExpect(status().isOk()).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        securityAnalysisStatus = mapper.readValue(resultAsString, SecurityAnalysisStatus.class);
        assertEquals(SecurityAnalysisStatus.NOT_DONE, securityAnalysisStatus);
    }

    @Test
    void stopTest() throws Exception {
        countDownLatch = new CountDownLatch(1);

        new Thread(() -> {
            try {
                MvcResult mvcResult;
                String resultAsString;

                mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_STOP_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me&variantId=" + VARIANT_TO_STOP_ID + "&loadFlowParametersUuid=" + UUID.randomUUID())
                    .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                    .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                    ).andReturn();

                resultAsString = mvcResult.getResponse().getContentAsString();
                UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
                assertEquals(RESULT_UUID, resultUuid);
            } catch (Exception e) {
                throw new RuntimeException(e.getMessage());
            }
        }).start();

        // wait for security analysis to actually run before trying to stop it
        countDownLatch.await();

        mockMvc.perform(put("/" + VERSION + "/results/" + RESULT_UUID + "/stop" + "?receiver=me")
                        .header(HEADER_USER_ID, "testUserId"))
                .andExpect(status().isOk());

        Message<byte[]> message = output.receive(TIMEOUT * 3, "sa.stopped");
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));
        assertEquals(getCancelMessage(COMPUTATION_TYPE), message.getHeaders().get("message"));
    }

    @Test
    void testStopAndFail() throws Exception {
        UUID randomUuid = UUID.randomUUID();
        mockMvc.perform(put("/" + VERSION + "/results/" + randomUuid + "/stop" + "?receiver=me")
                        .header(HEADER_USER_ID, "testUserId"))
                .andExpect(status().isOk());

        Message<byte[]> message = output.receive(TIMEOUT * 3, "sa.cancelfailed");
        assertEquals(randomUuid.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));
        assertEquals(getCancelFailedMessage(COMPUTATION_TYPE), message.getHeaders().get("message"));
    }

    @Test
    void runTestWithError() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        given(actionsService.getContingencyList(List.of(CONTINGENCY_LIST_ERROR_NAME), NETWORK_UUID, VARIANT_1_ID))
            .willThrow(new RuntimeException(ERROR_MESSAGE));

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_ERROR_NAME
            + "&receiver=me&variantId=" + VARIANT_1_ID + "&loadFlowParametersUuid=" + UUID.randomUUID())
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        // No result message
        assertNull(output.receive(TIMEOUT, "sa.result"));

        // No result
        assertResultNotFound(RESULT_UUID);
    }

    @Test
    void runWithReportTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME + "&provider=testProvider" + "&reportUuid=" + REPORT_UUID + "&reporterId=" + UUID.randomUUID() + "&loadFlowParametersUuid=" + UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON)
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON))
                    .andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    void runWithReportTestElementsNotFoundAndNotConnected() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(network);
        given(actionsService.getContingencyList(List.of(CONTINGENCY_LIST_NAME), NETWORK_UUID, null))
                .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME + "&provider=testProvider" + "&reportUuid=" + REPORT_UUID + "&reporterId=" + UUID.randomUUID() + "&loadFlowParametersUuid=" + UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON)
                        .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON))
                .andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));

        assertLogMessage("Equipments not found", "security.analysis.server.notFoundEquipments", reportService);
        assertLogMessage("Cannot find the following equipments wrongId1, wrongId2 in contingency l1", "security.analysis.server.contingencyEquipmentNotFound", reportService);

        assertLogMessage("Equipments not connected", "security.analysis.server.notConnectedEquipments", reportService);
        assertLogMessage("The following equipments notConnectedId1 in contingency l4 are not connected", "security.analysis.server.contingencyEquipmentNotConnected", reportService);
    }

    @Test
    void getProvidersTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(get("/" + VERSION + "/providers"))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        List<String> providers = mapper.readValue(resultAsString, new TypeReference<>() { });
        assertEquals(List.of("DynaFlow", "OpenLoadFlow"), providers);
    }

    @Test
    void getDefaultProviderTest() throws Exception {
        mockMvc.perform(get("/" + VERSION + "/default-provider"))
            .andExpectAll(
                status().isOk(),
                content().contentType(new MediaType(MediaType.TEXT_PLAIN, StandardCharsets.UTF_8)),
                content().string("OpenLoadFlow")
            );
    }

    @Test
    void getZippedCsvResults() throws Exception {
        // running computation to create result
        MvcResult mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
                + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow" + "&loadFlowParametersUuid=" + UUID.randomUUID())
                .header(HEADER_USER_ID, "testUserId")
                .contentType(MediaType.APPLICATION_JSON))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        String resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        Message<byte[]> resultMessage = output.receive(TIMEOUT, "sa.result");
        assertEquals(RESULT_UUID.toString(), resultMessage.getHeaders().get("resultUuid"));
        assertEquals("me", resultMessage.getHeaders().get("receiver"));

        checkAllZippedCsvResults();
    }

    private void checkAllZippedCsvResults() throws Exception {
        SQLStatementCountValidator.reset();
        checkZippedCsvResult("n-result", "/results/n-result-en.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Equipment", "Violation type", "Limit name", "Limit value (A or kV)", "Calculated value (A or kV)", "Load (%)", "Overload", "Side"))
                .enumValueTranslations(ENUM_TRANSLATIONS_EN)
                .build());
        /*
         * SELECT
         * assert result exists
         * get all results
         */
        assertRequestsCount(2, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("n-result", "/results/n-result-fr.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Ouvrage", "Type de contrainte", "Nom du seuil", "Valeur du seuil (A ou kV)", "Valeur calculée (A ou kV)", "Charge (%)", "Surcharge", "Côté"))
                .enumValueTranslations(ENUM_TRANSLATIONS_FR)
                .build());
        assertRequestsCount(2, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("nmk-contingencies-result", "/results/nmk-contingencies-result-en.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Contingency ID", "Status", "Constraint", "Violation type", "Limit name", "Limit value (A or kV)", "Calculated value (A or kV)", "Load (%)", "Overload", "Side"))
                .enumValueTranslations(ENUM_TRANSLATIONS_EN)
                .build());
        /*
         * SELECT
         * assert result exists
         * get all contingencies
         * join contingency_entity_contingency_elements
         * join contingency_limit_violation and subject_limit_violation
         */
        assertRequestsCount(4, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("nmk-contingencies-result", "/results/nmk-contingencies-result-fr.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Id aléa", "Statut", "Contrainte", "Type de contrainte", "Nom du seuil", "Valeur du seuil (A ou kV)", "Charge (%)", "Surcharge", "Côté"))
                .enumValueTranslations(ENUM_TRANSLATIONS_FR)
                .build());
        assertRequestsCount(4, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("nmk-constraints-result", "/results/nmk-constraints-result-en.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Constraint", "Contingency ID", "Status", "Violation type", "Limit name", "Limit value (A or kV)", "Calculated value (A or kV)", "Load (%)", "Overload", "Side"))
                .enumValueTranslations(ENUM_TRANSLATIONS_EN)
                .build());
        /*
         * SELECT
         * assert result exists
         * get all subject_limit_violations
         * join contingency_limit_violation
         * join contingency_entity_contingency_elements
         */
        assertRequestsCount(4, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("nmk-constraints-result", "/results/nmk-constraints-result-fr.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Contrainte", "ID aléa", "Statut", "Type de contrainte", "Nom du seuil", "Valeur du seuil (A ou kV)", "Valeur calculée (A ou kV)", "Charge (%)", "Surcharge", "Côté"))
                .enumValueTranslations(ENUM_TRANSLATIONS_FR)
                .build());
        assertRequestsCount(4, 0, 0, 0);
    }

    private void checkZippedCsvResult(String resultType, String resourcePath, CsvTranslationDTO csvTranslationDTO) throws Exception {
        // get csv file
        byte[] resultAsByteArray = mockMvc.perform(post("/" + VERSION + "/results/" + RESULT_UUID + "/" + resultType + "/csv")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(csvTranslationDTO)))
            .andExpectAll(
                status().isOk(),
                content().contentType(APPLICATION_OCTET_STREAM_VALUE)
            ).andReturn().getResponse().getContentAsByteArray();

        // get zip file stream
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(resultAsByteArray));
             ByteArrayOutputStream contentOutputStream = new ByteArrayOutputStream();
             ByteArrayOutputStream expectedContentOutputStream = new ByteArrayOutputStream()) {
            // get first entry
            ZipEntry zipEntry = zin.getNextEntry();
            // check zip entry name
            assertEquals(CsvExportUtils.CSV_RESULT_FILE_NAME, zipEntry.getName());

            // get entry content as outputStream
            StreamUtils.copy(zin, contentOutputStream);

            // get expected content as outputStream
            InputStream csvStream = getClass().getResourceAsStream(resourcePath);
            StreamUtils.copy(csvStream, expectedContentOutputStream);

            // using bytearray comparison to check BOM presence in CSV files
            Assertions.assertThat(expectedContentOutputStream.toByteArray()).isEqualTo(contentOutputStream.toByteArray());
            zin.closeEntry();
        }
    }

    private void assertResultNotFound(UUID resultUuid) throws Exception {
        mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/n-result"))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/nmk-contingencies-result/paged"))
            .andExpect(status().isNotFound());

        mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/nmk-constraints-result/paged"))
            .andExpect(status().isNotFound());
    }
}
