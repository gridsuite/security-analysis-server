/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.contingency.Contingency;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.DefaultUriBuilderFactory;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class ActionsService {

    private static final String ACTIONS_API_VERSION = "v1";

    private final RestTemplate restTemplate;

    @Autowired
    public ActionsService(RestTemplateBuilder builder,
                          @Value("${backing-services.actions-server.base-uri:http://actions-server/}") String baseUri) {
        this.restTemplate = Objects.requireNonNull(builder).uriTemplateHandler(new DefaultUriBuilderFactory(baseUri)).build();
    }

    public ActionsService(RestTemplate restTemplate) {
        this.restTemplate = Objects.requireNonNull(restTemplate);
    }

    public List<Contingency> getContingencyList(String name, UUID networkUuid) {
        Objects.requireNonNull(name);
        Objects.requireNonNull(networkUuid);
        ResponseEntity<List<Contingency>> response = restTemplate.exchange(ACTIONS_API_VERSION + "/contingency-lists/{name}/export?networkUuuid={networkUuuid}",
                                                                           HttpMethod.GET,
                                                                           null,
                                                                           new ParameterizedTypeReference<>() { },
                                                                           name,
                                                                           networkUuid.toString());
        if (response.getStatusCode() != HttpStatus.OK) {
            throw new ResponseStatusException(response.getStatusCode(), "Fail to get contingency list '" + name + "'");
        }
        return response.getBody();
    }
}
