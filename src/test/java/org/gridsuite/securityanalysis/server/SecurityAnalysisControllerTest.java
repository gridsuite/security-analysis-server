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
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.*;
import com.powsybl.security.results.PreContingencyResult;
import lombok.SneakyThrows;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.service.ActionsService;
import org.gridsuite.securityanalysis.server.service.ReportService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.gridsuite.securityanalysis.server.service.UuidGeneratorService;
import org.gridsuite.securityanalysis.server.util.CustomPageImpl;
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
import org.springframework.cloud.stream.binder.test.TestChannelBinderConfiguration;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.config.EnableSpringDataWebSupport;
import org.springframework.http.MediaType;
import org.springframework.messaging.Message;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.ContextHierarchy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.service.NotificationService.CANCEL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.NotificationService.FAIL_MESSAGE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */

@RunWith(SpringRunner.class)
@AutoConfigureMockMvc
@SpringBootTest
@EnableSpringDataWebSupport
@ContextHierarchy({@ContextConfiguration(classes = {SecurityAnalysisApplication.class, TestChannelBinderConfiguration.class})})
public class SecurityAnalysisControllerTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID NETWORK_STOP_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e6");
    private static final UUID RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5d");
    private static final UUID REPORT_UUID = UUID.fromString("0c4de370-3e6a-4d72-b292-d355a97e0d53");
    private static final UUID OTHER_RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5a");
    private static final UUID NETWORK_FOR_MERGING_VIEW_UUID = UUID.fromString("11111111-7977-4592-ba19-88027e4254e4");
    private static final UUID OTHER_NETWORK_FOR_MERGING_VIEW_UUID = UUID.fromString("22222222-7977-4592-ba19-88027e4254e4");
    private static final String NMK_CONTINGENCIES_PATH = "nmk-contingencies-result";
    private static final String NMK_CONSTRAINTS_PATH = "nmk-constraints-result";

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

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_1_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_2_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_3_ID);

        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(network);

        Network networkForMergingView = new NetworkFactoryImpl().createNetwork("mergingView", "test");
        given(networkStoreService.getNetwork(NETWORK_FOR_MERGING_VIEW_UUID, PreloadingStrategy.COLLECTION)).willReturn(networkForMergingView);

        Network otherNetworkForMergingView = new NetworkFactoryImpl().createNetwork("other", "test 2");
        given(networkStoreService.getNetwork(OTHER_NETWORK_FOR_MERGING_VIEW_UUID, PreloadingStrategy.COLLECTION)).willReturn(otherNetworkForMergingView);

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
            .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES_VARIANT);
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
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_FOR_MERGING_VIEW_UUID, null))
            .willReturn(SecurityAnalysisProviderMock.CONTINGENCIES);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, OTHER_NETWORK_FOR_MERGING_VIEW_UUID, null))
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
        MvcResult mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID)
                .contentType(MediaType.APPLICATION_JSON)
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

        // run with specific variant
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID + "&provider=OpenLoadFlow"))
                .andExpectAll(
                    status().isOk(),
                    content().contentType(MediaType.APPLICATION_JSON)
                ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT_VARIANT, new MatcherJson<>(mapper, securityAnalysisResult));

        // run with implicit initial variant
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME))
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

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
            + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow"))
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

        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/n-result"))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        PreContingencyResult preContingencyResult = mapper.readValue(resultAsString, PreContingencyResult.class);
        assertThat(RESULT.getPreContingencyResult(), new MatcherJson<>(mapper, preContingencyResult));

        /*mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-contingencies-result?page=0&size=3&contingencyId=l7"))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        Page<ContingencyToSubjectLimitViolationDTO> contingenciesToConstraints = mapper.readValue(resultAsString, new TypeReference<>() {
        });
        assertThat(RESULT_CONTINGENCIES, new MatcherJson<>(mapper, contingenciesToConstraints));*/

        mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/nmk-constraints-result?page=0&size=3"))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        CustomPageImpl<SubjectLimitViolationToContingencyDTO> constraintsToContingencies = mapper.readValue(resultAsString, new TypeReference<CustomPageImpl<SubjectLimitViolationToContingencyDTO>>() { });
        assertThat(constraintsToContingencies, new MatcherJson<>(mapper, new CustomPageImpl<>(RESULT_CONSTRAINTS, PageRequest.ofSize(3), RESULT_CONSTRAINTS.size())));

        // should throw not found if result does not exist
        assertResultNotFound(OTHER_RESULT_UUID);

        // test one result deletion
        mockMvc.perform(delete("/" + VERSION + "/results/" + RESULT_UUID))
                .andExpect(status().isOk());

        assertResultNotFound(RESULT_UUID);
    }

    @Test
    public void findNmKContingenciesResults() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow"))
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

        // test pagination
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, null , RESULT_CONTINGENCIES);
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 1, 2, null , RESULT_CONTINGENCIES);
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 25, null , RESULT_CONTINGENCIES);
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 1, 25, null , RESULT_CONTINGENCIES);

        // test sorting
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "sort=contingencyId,desc" , RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(ContingencyToSubjectLimitViolationDTO::getId).reversed()).toList());
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "sort=contingencyId" , RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(ContingencyToSubjectLimitViolationDTO::getId)).toList());

        // test filtering
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "acceptableDuration=" + LIMIT_VIOLATION_1.getAcceptableDuration(), resultFilteredByNestedIntegerField);
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "acceptableDuration="  + LIMIT_VIOLATION_1.getAcceptableDuration() + "&contingencyId=" + CONTINGENCIES.get(0).getId(),
            resultFilteredByNestedIntegerField.stream().filter(r -> r.getId().equals(CONTINGENCIES.get(0).getId())).toList());
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "contingencyId=" + CONTINGENCIES.get(0).getId() + "&subjectId=" + LIMIT_VIOLATION_1.getSubjectId(),
            resultFilteredByDeeplyNestedField.stream().filter(r -> r.getId().equals(CONTINGENCIES.get(0).getId())).toList());
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "limitType=" + LimitViolationType.HIGH_VOLTAGE, resultFilteredByNestedEnumField);
        testPaginatedResult(NMK_CONTINGENCIES_PATH, 0, 3, "acceptableDuration=" + LIMIT_VIOLATION_1.getAcceptableDuration() + "&", resultFilteredByNestedIntegerField);

    }

    @Test
    public void findNmKConstraintsResults() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow"))
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

        testPaginatedResult(NMK_CONSTRAINTS_PATH, 0, 3, null , RESULT_CONSTRAINTS);
        testPaginatedResult(NMK_CONSTRAINTS_PATH, 1, 2, null , RESULT_CONSTRAINTS);
        testPaginatedResult(NMK_CONSTRAINTS_PATH, 0, 25, null , RESULT_CONSTRAINTS);
        testPaginatedResult(NMK_CONSTRAINTS_PATH, 1, 25, null , RESULT_CONSTRAINTS);
    }

    private <T> void testPaginatedResult(String path, int page, int pageSize, String filterandSortQuery, List<T> expectedResult) throws Exception {
        MvcResult mvcResult = mockMvc.perform(get("/" + VERSION + "/results/" + RESULT_UUID + "/" + path + "?page=" + page + "&size=" + pageSize + "&" + filterandSortQuery))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        String resultAsString = mvcResult.getResponse().getContentAsString();
        CustomPageImpl<T> contingenciesToSubjectLimitViolations = mapper.readValue(resultAsString, new TypeReference<>() {
        });

        Pageable pageRequest = PageRequest.of(page, pageSize);
        int start = Math.min((int)pageRequest.getOffset(), expectedResult.size());
        int end = Math.min((start + pageRequest.getPageSize()), expectedResult.size());

        assertThat(contingenciesToSubjectLimitViolations, new MatcherJson<>(mapper, new CustomPageImpl<>(expectedResult.subList(start, end), pageRequest, expectedResult.size())));
    }

    @Test
    public void runWithTwoLists() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME +
            "&contingencyListName=" + CONTINGENCY_LIST2_NAME + "&variantId=" + VARIANT_1_ID))
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

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME))
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
    public void mergingViewTest() throws Exception {
        MvcResult mvcResult;
        String resultAsString;

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_FOR_MERGING_VIEW_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME + "&networkUuid=" + OTHER_NETWORK_FOR_MERGING_VIEW_UUID))
            .andExpectAll(
                status().isOk(),
                content().contentType(MediaType.APPLICATION_JSON)
            ).andReturn();

        resultAsString = mvcResult.getResponse().getContentAsString();
        SecurityAnalysisResult securityAnalysisResult = mapper.readValue(resultAsString, SecurityAnalysisResult.class);
        assertThat(RESULT, new MatcherJson<>(mapper, securityAnalysisResult));
    }

    @Test
    public void testStatus() throws Exception {
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
        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
            + "&receiver=me&variantId=" + VARIANT_2_ID + "&provider=OpenLoadFlow"))
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
                mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_STOP_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me&variantId=" + VARIANT_TO_STOP_ID))
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

        given(actionsService.getContingencyList(CONTINGENCY_LIST_ERROR_NAME, NETWORK_UUID, VARIANT_1_ID))
            .willThrow(new RuntimeException(ERROR_MESSAGE));

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_ERROR_NAME
            + "&receiver=me&variantId=" + VARIANT_1_ID))
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

        mvcResult = mockMvc.perform(post("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME + "&provider=testProvider" + "&reportUuid=" + REPORT_UUID + "&reporterId=" + UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON))
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
        assertEquals(List.of("DynaFlow", "OpenLoadFlow", "Hades2"), providers);
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

    private void assertResultNotFound(UUID resultUuid) throws Exception {
        mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/n-result"))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/nmk-contingencies-result"))
            .andExpect(status().isNotFound());

        mockMvc.perform(get("/" + VERSION + "/results/" + resultUuid + "/nmk-constraints-result"))
            .andExpect(status().isNotFound());
    }
}
