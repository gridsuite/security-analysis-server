/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class ActionsService {

    static final String ACTIONS_API_VERSION = "v1";

    private static final String DELIMITER = "/";

    private String baseUri;

    private RestTemplate restTemplate;

    public void setActionServiceBaseUri(String baseUri) {
        this.baseUri = baseUri;
    }

    public ActionsService(
            @Value("${gridsuite.services.actions-server.base-uri:http://actions-server/}") String baseUri,
            RestTemplate restTemplate) {
        this.baseUri = baseUri;
        this.restTemplate = restTemplate;
    }

    public List<ContingencyInfos> getContingencyList(List<String> ids, UUID networkUuid, String variantId) {
        Objects.requireNonNull(ids);
        Objects.requireNonNull(networkUuid);
        if (ids.isEmpty()) {
            throw new IllegalArgumentException("List 'ids' must not be null or empty");
        }

        URI path = UriComponentsBuilder
                .fromPath(DELIMITER + ACTIONS_API_VERSION + "/contingency-lists/contingency-infos/export")
                .queryParam("networkUuid", networkUuid.toString())
                .queryParamIfPresent("variantId", Optional.ofNullable(variantId))
                .queryParam("ids", ids)
                .build().toUri();

        return restTemplate.exchange(baseUri + path, HttpMethod.GET, null, new ParameterizedTypeReference<List<ContingencyInfos>>() { }).getBody();
    }
}
