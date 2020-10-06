/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.contingency.Contingency;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class ActionsService {

    static final String ACTIONS_API_VERSION = "v1";

    private final WebClient webClient;

    @Autowired
    public ActionsService(WebClient.Builder builder,
                          @Value("${backing-services.actions-server.base-uri:http://actions-server/}") String baseUri) {
        webClient = builder.baseUrl(baseUri)
                .build();
    }

    public ActionsService(WebClient webClient) {
        this.webClient = Objects.requireNonNull(webClient);
    }

    public Mono<List<Contingency>> getContingencyList(String name, UUID networkUuid) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(networkUuid);
        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .path(ACTIONS_API_VERSION + "/contingency-lists/{name}/export")
                        .queryParam("networkUuid", networkUuid.toString())
                        .build(name))
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<>() { });
    }
}
