/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class RestClientConfigTest {
    enum State { READY }

    @Test
    void suppliesJackson2WhenMissing() {
        RestClient.Builder builder = RestClient.builder().messageConverters(converters ->
            converters.removeIf(MappingJackson2HttpMessageConverter.class::isInstance));
        assertCaseInsensitiveEnum(builder);
    }

    @Test
    void replacesExistingJackson2() {
        RestClient.Builder builder = RestClient.builder().messageConverters(converters -> {
            converters.clear();
            converters.add(new MappingJackson2HttpMessageConverter());
        });
        assertCaseInsensitiveEnum(builder);
    }

    private void assertCaseInsensitiveEnum(RestClient.Builder builder) {
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        RestClient client = new RestClientConfig().restClient(builder);
        server.expect(requestTo("/state")).andRespond(withSuccess("\"ready\"", MediaType.APPLICATION_JSON));
        assertEquals(State.READY, client.get().uri("/state").retrieve().body(State.class));
        server.verify();
    }
}
