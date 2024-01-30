/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.reporter.Reporter;
import com.powsybl.iidm.network.Branch;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.*;
import com.vladmihalcea.sql.SQLStatementCountValidator;

import lombok.SneakyThrows;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.service.ActionsService;
import org.gridsuite.securityanalysis.server.service.ReportService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.gridsuite.securityanalysis.server.service.UuidGeneratorService;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;
import org.gridsuite.securityanalysis.server.util.MatcherJson;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cloud.stream.binder.test.OutputDestination;
import org.springframework.http.MediaType;
import org.springframework.messaging.Message;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.StreamUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.service.NotificationService.CANCEL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.NotificationService.FAIL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.NotificationService.HEADER_USER_ID;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.*;
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

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
@SpringBootTest
@ContextConfigurationWithTestChannel
public class SecurityAnalysisControllerTest {

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

    @MockBean
    private UuidGeneratorService uuidGeneratorService;

    @Autowired
    private SecurityAnalysisWorkerService workerService;

    @Autowired
    private ObjectMapper mapper;

    private final Map<String, String> enumTranslationsEn = Map.of(
        "ONE", "Side 1",
        "TWO", "Side 2",
        "CURRENT", "Current",
        "HIGH_VOLTAGE", "High voltage",
        "FAILED", "Failed",
        "CONVERGED", "Converged"
    );

    private final Map<String, String> enumTranslationsFr = Map.of(
        "ONE", "Côté 1",
        "TWO", "Côté 2",
        "CURRENT", "Intensité",
        "HIGH_VOLTAGE", "Tension haute",
        "FAILED", "Echec",
        "CONVERGED", "Convergence"
    );

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_1_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_2_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_3_ID);

        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(network);

        when(networkStoreService.getNetwork(NETWORK_STOP_UUID, PreloadingStrategy.COLLECTION)).thenAnswer((Answer) invocation -> {
            //Needed so the stop call doesn't arrive too late
            Network network1 = new NetworkFactoryImpl().createNetwork("other", "test");
            network1.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_TO_STOP_ID);
            return network1;
        });

        // action service mocking
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, VARIANT_1_ID))
                .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME_VARIANT, NETWORK_UUID, VARIANT_3_ID))
            .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES_VARIANT.stream().map(ContingencyInfos::new).collect(Collectors.toList()));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, VARIANT_2_ID))
            .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, null))
            .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST2_NAME, NETWORK_UUID, VARIANT_1_ID))
                .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_STOP_UUID, VARIANT_2_ID))
                .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST2_NAME, NETWORK_STOP_UUID, VARIANT_2_ID))
                .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_ERROR_NAME, NETWORK_UUID, VARIANT_1_ID))
                .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_STOP_UUID, VARIANT_TO_STOP_ID))
            .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);

        // UUID service mocking to always generate the same result UUID
        given(uuidGeneratorService.generate()).willReturn(RESULT_UUID);

        doNothing().when(reportService).sendReport(any(UUID.class), any(Reporter.class));

        // SecurityAnalysis.Runner constructor is private..
        Constructor<SecurityAnalysis.Runner> constructor = SecurityAnalysis.Runner.class.getDeclaredConstructor(SecurityAnalysisProvider.class);
        constructor.setAccessible(true);
        SecurityAnalysis.Runner runner = constructor.newInstance(new SecurityAnalysisProviderMock());
        // mock the powsybl security analysis
        workerService.setSecurityAnalysisFactorySupplier(provider -> runner);

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
    @After
    public void tearDown() throws Exception {
        mockMvc.perform(delete("/" + VERSION + "/results"))
                .andExpect(status().isOk());
    }

    @SneakyThrows
    public void simpleRunRequest(SecurityAnalysisParametersInfos lfParams) {
        MvcResult mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID)
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
    @SneakyThrows
    public void runTestWithLFParams() {
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
    public void runTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

        // run with specific variant
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID + "&provider=OpenLoadFlow")
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT_VARIANT, new MatcherJson<>(mapper, securityAnalysisResult));

        // run with implicit initial variant
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME)
           .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
           .andExpectAll(
               status().isOk(),
               content().contentType(MediaType.APPLICATION_JSON)
           ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    public void runAndSaveTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

        SQLStatementCountValidator.reset();
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
            + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow")
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
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

        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-contingencies-result/paged"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON));

        mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-constraints-result/paged"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON));

        // should throw not found if result does not exist
        assertResultNotFound(OTHER_RESULT_UUID);

        // test one result deletion
        mockMvc.perform(delete("/" + VERSION + "/results/" + RESULT_UUID))
                .andExpect(status().isOk());

        assertResultNotFound(RESULT_UUID);
    }

    private String buildFilterUrl() {
        String filterUrl = "";
        try {

            List<ResourceFilterDTO> filters = List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "vl1", ResourceFilterDTO.Column.SUBJECT_ID),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, new String[]{"HIGH_VOLTAGE"}, ResourceFilterDTO.Column.LIMIT_TYPE),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.GREATER_THAN_OR_EQUAL, "399", ResourceFilterDTO.Column.LIMIT),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.LESS_THAN_OR_EQUAL, "420", ResourceFilterDTO.Column.VALUE),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.NOT_EQUAL, "2", ResourceFilterDTO.Column.ACCEPTABLE_DURATION)
            );

            String jsonFilters = new ObjectMapper().writeValueAsString(filters);

            filterUrl = "filters=" + URLEncoder.encode(jsonFilters, StandardCharsets.UTF_8.toString());

            return filterUrl;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return filterUrl;
    }

    private void assertFiltredResultN() throws Exception {

        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/n-result?" + buildFilterUrl()))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();
        String resultAsString = mvcResult.getResponse().getContentAsString();
        List<PreContingencyLimitViolationResultDTO> preContingencyResult = mapper.readValue(resultAsString, new TypeReference<List<PreContingencyLimitViolationResultDTO>>() { });
        assertEquals(1, preContingencyResult.size());
    }

    @Test
    public void runWithTwoLists() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME +
            "&contingencyListName=" + CONTINGENCY_LIST2_NAME + "&variantId=" + VARIANT_1_ID)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos))
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
    public void deleteResultsTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME)
            .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
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
    public void testStatus() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

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
            + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow")
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
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
    public void stopTest() throws Exception {
        countDownLatch = new CountDownLatch(1);

        new Thread(() -> {
            try {
                MvcResult mvcResult;
                String resultAsString;
                LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

                mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_STOP_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me&variantId=" + VARIANT_TO_STOP_ID)
                    .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
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

        mockMvc.perform(put("/" + VERSION + "/results/" + RESULT_UUID + "/stop"
            + "?receiver=me"))
                .andExpect(status().isOk());

        Message<byte[]> message = output.receive(TIMEOUT * 3, "sa.stopped");
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));
        assertEquals(CANCEL_MESSAGE, message.getHeaders().get("message"));
    }

    @Test
    public void runTestWithError() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

        given(actionsService.getContingencyList(CONTINGENCY_LIST_ERROR_NAME, NETWORK_UUID, VARIANT_1_ID))
            .willThrow(new RuntimeException(ERROR_MESSAGE));

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_ERROR_NAME
            + "&receiver=me&variantId=" + VARIANT_1_ID)
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        UUID resultUuid = mapper.readValue(resultAsString, UUID.class);
        assertEquals(RESULT_UUID, resultUuid);

        // Message stopped has been sent
        Message<byte[]> cancelMessage = output.receive(TIMEOUT, "sa.failed");
        assertEquals(RESULT_UUID.toString(), cancelMessage.getHeaders().get("resultUuid"));
        assertEquals("me", cancelMessage.getHeaders().get("receiver"));
        assertEquals(FAIL_MESSAGE + " : " + ERROR_MESSAGE, cancelMessage.getHeaders().get("message"));

        // No result
        assertResultNotFound(RESULT_UUID);
    }

    @Test
    public void runWithReportTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME + "&provider=testProvider" + "&reportUuid=" + REPORT_UUID + "&reporterId=" + UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON)
                .header(HEADER_USER_ID, "testUserId")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(loadFlowParametersInfos)))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON))
                    .andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    public void getProvidersTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(get("/" + VERSION + "/providers"))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        List<String> providers = mapper.readValue(resultAsString, new TypeReference<List<String>>() { });
        assertEquals(List.of("DynaFlow", "OpenLoadFlow"), providers); // WHY Dynaflow ???
    }

    @Test
    public void getDefaultProviderTest() throws Exception {
        mockMvc.perform(get("/" + VERSION + "/default-provider"))
            .andExpectAll(
                status().isOk(),
                content().contentType(new MediaType(MediaType.TEXT_PLAIN, StandardCharsets.UTF_8)),
                content().string("OpenLoadFlow")
            );
    }

    @Test
    public void geLimitTypesTest() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/limit-types"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        String resultAsString = mvcResult.getResponse().getContentAsString();
        List<LimitViolationType> limitTypes = mapper.readValue(resultAsString, new TypeReference<>() { });
        assertEquals(6, limitTypes.size());
        assertTrue(limitTypes.contains(LimitViolationType.ACTIVE_POWER));
        assertFalse(limitTypes.contains(LimitViolationType.HIGH_SHORT_CIRCUIT_CURRENT));
    }

    @Test
    public void geBranchSidesTest() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/branch-sides"))
                .andExpectAll(
                        status().isOk(),
                        content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        String resultAsString = mvcResult.getResponse().getContentAsString();
        List<Branch.Side> sides = mapper.readValue(resultAsString, new TypeReference<>() { });
        assertEquals(2, sides.size());
        assertTrue(sides.contains(Branch.Side.ONE));
        assertTrue(sides.contains(Branch.Side.TWO));
    }

    @Test
    public void getComputationStatus() throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/computation-status"))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        String resultAsString = mvcResult.getResponse().getContentAsString();
        List<LoadFlowResult.ComponentResult.Status> status = mapper.readValue(resultAsString, new TypeReference<>() { });
        assertEquals(status, Arrays.asList(LoadFlowResult.ComponentResult.Status.values()));
    }

    @Test
    public void getZippedCsvResults() throws Exception {
        LoadFlowParametersInfos loadFlowParametersInfos = new LoadFlowParametersInfos(null, null);
        // running computation to create result
        MvcResult mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?reportType=SecurityAnalysis&contingencyListName=" + CONTINGENCY_LIST_NAME
                + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow")
                .header(HEADER_USER_ID, "testUserId")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(loadFlowParametersInfos)))
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

    public void checkAllZippedCsvResults() throws Exception {
        SQLStatementCountValidator.reset();
        checkZippedCsvResult("n-result", "/results/n-result-en.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Equipment", "Violation type", "Limit name", "Limit value (A or kV)", "Calculated value (A or kV)", "Load (%)", "Overload", "Side"))
                .enumValueTranslations(enumTranslationsEn)
                .build());
        /**
         * SELECT
         * assert result exists
         * get all results
         */
        assertRequestsCount(2, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("n-result", "/results/n-result-fr.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Ouvrage", "Type de contrainte", "Nom du seuil", "Valeur du seuil (A ou kV)", "Valeur calculée (A ou kV)", "Charge (%)", "Surcharge", "Côté"))
                .enumValueTranslations(enumTranslationsFr)
                .build());
        assertRequestsCount(2, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("nmk-contingencies-result", "/results/nmk-contingencies-result-en.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Contingency ID", "Status", "Constraint", "Violation type", "Limit name", "Limit value (A or kV)", "Calculated value (A or kV)", "Load (%)", "Overload", "Side"))
                .enumValueTranslations(enumTranslationsEn)
                .build());
        /**
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
                .enumValueTranslations(enumTranslationsFr)
                .build());
        assertRequestsCount(4, 0, 0, 0);

        SQLStatementCountValidator.reset();
        checkZippedCsvResult("nmk-constraints-result", "/results/nmk-constraints-result-en.csv",
            CsvTranslationDTO.builder()
                .headers(List.of("Constraint", "Contingency ID", "Status", "Violation type", "Limit name", "Limit value (A or kV)", "Calculated value (A or kV)", "Load (%)", "Overload", "Side"))
                .enumValueTranslations(enumTranslationsEn)
                .build());
        /**
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
                .enumValueTranslations(enumTranslationsFr)
                .build());
        assertRequestsCount(4, 0, 0, 0);
    }

    public void checkZippedCsvResult(String resultType, String resourcePath, CsvTranslationDTO csvTranslationDTO) throws Exception {
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

            assertEquals(expectedContentOutputStream.toString(), contentOutputStream.toString());
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
