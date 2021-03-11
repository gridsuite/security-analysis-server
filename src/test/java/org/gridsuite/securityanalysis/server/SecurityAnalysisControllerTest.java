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
import org.gridsuite.securityanalysis.server.service.ActionsService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisConfigService;
import org.gridsuite.securityanalysis.server.service.UuidGeneratorService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
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

import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisFactoryMock.*;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisStoppedPublisherService.CANCEL_MESSAGE;
import static org.gridsuite.securityanalysis.server.service.SecurityAnalysisStoppedPublisherService.FAIL_MESSAGE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.BDDMockito.given;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RunWith(SpringRunner.class)
@AutoConfigureWebTestClient
@EnableWebFlux
@SpringBootTest
@ContextHierarchy({@ContextConfiguration(classes = {SecurityAnalysisApplication.class, TestChannelBinderConfiguration.class})})
public class SecurityAnalysisControllerTest extends AbstractEmbeddedCassandraSetup {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID OTHER_NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e5");
    private static final UUID RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5d");
    private static final UUID OTHER_RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5a");

    private static final String EXPECTED_JSON = "{\"version\":\"1.0\",\"preContingencyResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"l3\",\"limitType\":\"CURRENT\",\"acceptableDuration\":1200,\"limit\":10.0,\"limitReduction\":1.0,\"value\":11.0,\"side\":\"ONE\"}],\"actionsTaken\":[]},\"postContingencyResults\":[{\"contingency\":{\"id\":\"l1\",\"elements\":[{\"id\":\"l1\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"vl1\",\"limitType\":\"HIGH_VOLTAGE\",\"acceptableDuration\":0,\"limit\":400.0,\"limitReduction\":1.0,\"value\":410.0}],\"actionsTaken\":[]}},{\"contingency\":{\"id\":\"l2\",\"elements\":[{\"id\":\"l2\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"vl1\",\"limitType\":\"HIGH_VOLTAGE\",\"acceptableDuration\":0,\"limit\":400.0,\"limitReduction\":1.0,\"value\":410.0}],\"actionsTaken\":[]}}]}";

    private static final String EXPECTED_FILTERED_JSON = "{\"version\":\"1.0\",\"preContingencyResult\":{\"computationOk\":true,\"limitViolations\":[{\"subjectId\":\"l3\",\"limitType\":\"CURRENT\",\"acceptableDuration\":1200,\"limit\":10.0,\"limitReduction\":1.0,\"value\":11.0,\"side\":\"ONE\"}],\"actionsTaken\":[]},\"postContingencyResults\":[{\"contingency\":{\"id\":\"l1\",\"elements\":[{\"id\":\"l1\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]}},{\"contingency\":{\"id\":\"l2\",\"elements\":[{\"id\":\"l2\",\"type\":\"BRANCH\"}]},\"limitViolationsResult\":{\"computationOk\":true,\"limitViolations\":[],\"actionsTaken\":[]}}]}";

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

    @Autowired
    private SecurityAnalysisConfigService configService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create();
        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(network);

        Network otherNetwork = Network.create("other", "test");
        given(networkStoreService.getNetwork(OTHER_NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(otherNetwork);

        // action service mocking
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID))
                .willReturn(Flux.fromIterable(SecurityAnalysisFactoryMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST2_NAME, NETWORK_UUID))
                .willReturn(Flux.fromIterable(SecurityAnalysisFactoryMock.CONTINGENCIES));
        given(actionsService.getContingencyList(CONTINGENCY_LIST_ERROR_NAME, NETWORK_UUID))
                .willReturn(Flux.fromIterable(SecurityAnalysisFactoryMock.CONTINGENCIES).thenMany(Flux.error(new RuntimeException(ERROR_MESSAGE))));

        // UUID service mocking to always generate the same result UUID
        given(uuidGeneratorService.generate()).willReturn(RESULT_UUID);

        // mock the powsybl security analysis service
        configService.setSecurityAnalysisFactoryClass(SecurityAnalysisFactoryMock.class.getName());

        // purge messages
        while (output.receive(1000) != null) {
        }
    }

    @Test
    public void runTest() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(String.class)
                .isEqualTo(EXPECTED_JSON);
    }

    @Test
    public void runAndSaveTest() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        Message<byte[]> resultMessage = output.receive(1000, "sa.result.destination");
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
                        "&contingencyListName=" + CONTINGENCY_LIST2_NAME)
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

        output.receive(1000, "sa.result.destination");

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
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME + "&networkUuid=" + OTHER_NETWORK_UUID)
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
                .uri("/" + VERSION + "/results/" + RESULT_UUID + "/invalidate-status")
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
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_NAME
                        + "&receiver=me")
                .exchange()
                .expectStatus().isOk()
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        Message<byte[]> message = output.receive(1000, "sa.run.destination");
        assertEquals(NETWORK_UUID.toString(), message.getHeaders().get("networkUuid"));
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals(CONTINGENCY_LIST_NAME, message.getHeaders().get("contingencyListNames"));
        assertEquals("me", message.getHeaders().get("receiver"));

        webTestClient.put()
                .uri("/" + VERSION + "/results/" + RESULT_UUID + "/stop"
                        + "?receiver=me")
                .exchange()
                .expectStatus().isOk();

        message = output.receive(1000, "sa.cancel.destination");
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));

        message = output.receive(1000, "sa.stopped.destination");
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));
        assertEquals(CANCEL_MESSAGE, message.getHeaders().get("message"));

        assertNull(output.receive(1000));
    }

    @Test
    public void runTestWithError() {
        webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run-and-save?contingencyListName=" + CONTINGENCY_LIST_ERROR_NAME
                        + "&receiver=me")
                .exchange()
                .expectStatus().isOk()  // Because fully asynchronous (just publish a message)
                .expectHeader().contentType(MediaType.APPLICATION_JSON)
                .expectBody(UUID.class)
                .isEqualTo(RESULT_UUID);

        Message<byte[]> message = output.receive(1000, "sa.run.destination");
        assertEquals(NETWORK_UUID.toString(), message.getHeaders().get("networkUuid"));
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals(CONTINGENCY_LIST_ERROR_NAME, message.getHeaders().get("contingencyListNames"));
        assertEquals("me", message.getHeaders().get("receiver"));

        // Message stopped has been sent
        message = output.receive(1000, "sa.stopped.destination");
        assertEquals(RESULT_UUID.toString(), message.getHeaders().get("resultUuid"));
        assertEquals("me", message.getHeaders().get("receiver"));
        assertEquals(FAIL_MESSAGE + " : " + ERROR_MESSAGE, message.getHeaders().get("message"));

        assertNull(output.receive(1000));

        // No result
        webTestClient.get()
                .uri("/" + VERSION + "/results/" + RESULT_UUID)
                .exchange()
                .expectStatus().isNotFound();
    }
}
