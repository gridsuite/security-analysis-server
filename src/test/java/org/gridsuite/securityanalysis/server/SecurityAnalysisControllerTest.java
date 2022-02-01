/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisProvider;

import org.gridsuite.securityanalysis.server.service.ActionsService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisWorkerService;
import org.gridsuite.securityanalysis.server.service.UuidGeneratorService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.cloud.stream.binder.test.OutputDestination;
import org.springframework.cloud.stream.binder.test.TestChannelBinderConfiguration;
import org.springframework.http.MediaType;
import org.springframework.messaging.Message;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.ContextHierarchy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.config.EnableWebFlux;
import reactor.core.publisher.Flux;

import java.lang.reflect.Constructor;
import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisStoppedPublisherService.CANCEL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisStoppedPublisherService.FAIL_MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.when;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RunWith(SpringRunner.class)
@AutoConfigureWebTestClient
@EnableWebFlux
@SpringBootTest
@ContextHierarchy({@ContextConfiguration(classes = {SecurityAnalysisApplication.class, TestChannelBinderConfiguration.class})})
public class SecurityAnalysisControllerTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID NETWORK_STOP_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e6");
    private static final UUID RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5d");
    private static final UUID OTHER_RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5a");
    private static final UUID NETWORK_FOR_MERGING_VIEW_UUID = UUID.fromString("11111111-7977-4592-ba19-88027e4254e4");
    private static final UUID OTHER_NETWORK_FOR_MERGING_VIEW_UUID = UUID.fromString("22222222-7977-4592-ba19-88027e4254e4");

    private static final String EXPECTED_JSON = "{\"version\":\"1.1\",\"preContingencyResult\":{\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"l3\",\"limitType\":\"CURRENT\",\"acceptableDuration\":1200,\"limit\":10.0,\"limitReduction\":1.0,\"value\":11.0,\"side\":\"ONE\"}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]},\"postContingencyResults\":[{\"contingency\":{\"id\":\"l1\",\"elements\":[{\"id\":\"l1\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"vl1\",\"limitType\":\"HIGH_VOLTAGE\",\"acceptableDuration\":0,\"limit\":400.0,\"limitReduction\":1.0,\"value\":410.0}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]},{\"contingency\":{\"id\":\"l2\",\"elements\":[{\"id\":\"l2\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"vl1\",\"limitType\":\"HIGH_VOLTAGE\",\"acceptableDuration\":0,\"limit\":400.0,\"limitReduction\":1.0,\"value\":410.0}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]}]}";

    private static final String EXPECTED_JSON_VARIANT = "{\"version\":\"1.1\",\"preContingencyResult\":{\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"l6\",\"limitType\":\"CURRENT\",\"acceptableDuration\":1200,\"limit\":10.0,\"limitReduction\":1.0,\"value\":11.0,\"side\":\"ONE\"}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]},\"postContingencyResults\":[{\"contingency\":{\"id\":\"l3\",\"elements\":[{\"id\":\"l3\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"vl7\",\"limitType\":\"HIGH_VOLTAGE\",\"acceptableDuration\":0,\"limit\":400.0,\"limitReduction\":1.0,\"value\":410.0}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]},{\"contingency\":{\"id\":\"l4\",\"elements\":[{\"id\":\"l4\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"vl7\",\"limitType\":\"HIGH_VOLTAGE\",\"acceptableDuration\":0,\"limit\":400.0,\"limitReduction\":1.0,\"value\":410.0}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]}]}";

    private static final String EXPECTED_FILTERED_JSON = "{\"version\":\"1.1\",\"preContingencyResult\":{\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"l3\",\"limitType\":\"CURRENT\",\"acceptableDuration\":1200,\"limit\":10.0,\"limitReduction\":1.0,\"value\":11.0,\"side\":\"ONE\"}],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]},\"postContingencyResults\":[{\"contingency\":{\"id\":\"l1\",\"elements\":[{\"id\":\"l1\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]},{\"contingency\":{\"id\":\"l2\",\"elements\":[{\"id\":\"l2\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]},\"branchResults\":[],\"busResults\":[],\"threeWindingsTransformerResults\":[]}]}";

    private static final String ERROR_MESSAGE = "Error message test";

    @Autowired
    private OutputDestination output;

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private NetworkStoreService networkStoreService;

    @MockBean
    private ActionsService actionsService;

    @MockBean
    private UuidGeneratorService uuidGeneratorService;

    @SpyBean
    private SecurityAnalysisWorkerService workerService;

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
            Thread.sleep(2000);
            Network network1 = new NetworkFactoryImpl().createNetwork("other", "test");
            network1.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_2_ID);
            return network1;
        });

        // action service mocking
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, VARIANT_1_ID))
                .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME_VARIANT, NETWORK_UUID, VARIANT_3_ID))
            .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES_VARIANT));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, VARIANT_2_ID))
            .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, null))
            .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST2_NAME, NETWORK_UUID, VARIANT_1_ID))
                .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_STOP_UUID, VARIANT_2_ID))
                .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST2_NAME, NETWORK_STOP_UUID, VARIANT_2_ID))
                .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_ERROR_NAME, NETWORK_UUID, VARIANT_1_ID))
                .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES).thenMany(Flux.error(new RuntimeException(ERROR_MESSAGE))));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_FOR_MERGING_VIEW_UUID, null))
            .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, OTHER_NETWORK_FOR_MERGING_VIEW_UUID, null))
            .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));

        // UUID service mocking to always generate the same result UUID
        given(uuidGeneratorService.generate()).willReturn(RESULT_UUID);

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
    }

    @Test
    public void runTest() {
        // run with specific variant
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME_VARIANT + "&variantId=" + VARIANT_3_ID)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .isEqualTo(EXPECTED_JSON_VARIANT);

        // run with implicit initial variant
        webTestClient.post()
            .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME)
            .exchange()
            .expectStatus().isOk()
            .expectHeader().contentType(MediaType.APPLICATION_JSON)
            .expectBody(String.class)
            .isEqualTo(EXPECTED_JSON);
    }

    @Test
    public void runAndSaveTest() throws InterruptedException {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me&variantId=" + VARIANT_2_ID)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        Message<byte[]> resultMessage = output.receive(1000, "sa.result");
        assertEquals(RESULT_UUID.toString(), resultMessage.getHeaders().get("resultUuid"));
        assertEquals("me", resultMessage.getHeaders().get("receiver"));

        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .isEqualTo(EXPECTED_JSON);

        // test limit type filtering
        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID + "?limitType=CURRENT")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .isEqualTo(EXPECTED_FILTERED_JSON);

        // should throw not found if result does not exist
        webTestClient.get()
                .uri("/" + VERSION + "/results/" + OTHER_RESULT_UUID)
                .exchange()
                .expectStatus().isNotFound();

        // test one result deletion
        webTestClient.delete()
                .uri("/" + VERSION + "/results/" + RESULT_UUID)
                .exchange()
                .expectStatus().isOk();

        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    public void runWithTwoLists() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME +
                        "&contingencyListName=" + CONTINGENCY_LIST2_NAME + "&variantId=" + VARIANT_1_ID)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .isEqualTo(EXPECTED_JSON);
    }

    @Test
    public void deleteResultsTest() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        output.receive(1000, "sa.result");

        webTestClient.delete()
                .uri("/" + VERSION + "/results")
                .exchange()
                .expectStatus().isOk();

        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID)
                .exchange()
                .expectStatus().isNotFound();
    }

    @Test
    public void mergingViewTest() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_FOR_MERGING_VIEW_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME + "&networkUuid=" + OTHER_NETWORK_FOR_MERGING_VIEW_UUID)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .isEqualTo(EXPECTED_JSON);
    }

    @Test
    public void testStatus() {
        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID + "/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .isEqualTo(null);

        webTestClient.put()
                .uri("/" + VERSION + "/results/invalidate-status?resultUuid=" + RESULT_UUID)
                .exchange()
                .expectStatus().isOk();

        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID + "/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .isEqualTo("NOT_DONE");
    }

    @Test
    public void stopTest() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_STOP_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me&variantId=" + VARIANT_2_ID)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        webTestClient.put()
                .uri("/" + VERSION + "/results/" + RESULT_UUID + "/stop"
                        + "?receiver=me")
                .exchange()
                .expectStatus().isOk();

        Message<byte[]> message = output.receive(3000, "sa.stopped");
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));
        assertEquals(CANCEL_MESSAGE, message.getHeaders().get("message"));
    }

    @Test
    public void runTestWithError() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_ERROR_NAME
                        + "&receiver=me&variantId=" + VARIANT_1_ID)
                .exchange()
                .expectStatus().isOk()  // Because fully asynchronous (just publish a message)
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        // Message stopped has been sent
        Message<byte[]> cancelMessage = output.receive(1000, "sa.stopped");
        assertEquals(RESULT_UUID.toString(), cancelMessage.getHeaders().get("resultUuid"));
        assertEquals("me", cancelMessage.getHeaders().get("receiver"));
        assertEquals(FAIL_MESSAGE + " : " + ERROR_MESSAGE, cancelMessage.getHeaders().get("message"));

        // No result
        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID)
                .exchange()
                .expectStatus().isNotFound();
    }
}
