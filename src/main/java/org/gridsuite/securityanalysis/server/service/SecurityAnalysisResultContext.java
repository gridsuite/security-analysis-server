/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.commons.PowsyblException;
import com.powsybl.security.SecurityAnalysisParameters;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;

import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisResultContext {

    private static final String REPORT_UUID = "reportUuid";

    private final UUID resultUuid;

    private final SecurityAnalysisRunContext runContext;

    public SecurityAnalysisResultContext(UUID resultUuid, SecurityAnalysisRunContext runContext) {
        this.resultUuid = Objects.requireNonNull(resultUuid);
        this.runContext = Objects.requireNonNull(runContext);
    }

    public UUID getResultUuid() {
        return resultUuid;
    }

    public SecurityAnalysisRunContext getRunContext() {
        return runContext;
    }

    private static List<String> getHeaderList(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null || header.isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.asList(header.split(","));
    }

    private static String getNonNullHeader(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null) {
            throw new PowsyblException("Header '" + name + "' not found");
        }
        return header;
    }

    public static SecurityAnalysisResultContext fromMessage(Message<String> message, ObjectMapper objectMapper) {
        Objects.requireNonNull(message);
        MessageHeaders headers = message.getHeaders();
        UUID resultUuid = UUID.fromString(getNonNullHeader(headers, "resultUuid"));
        UUID networkUuid = UUID.fromString(getNonNullHeader(headers, "networkUuid"));
        String variantId = (String) headers.get("variantId");
        List<UUID> otherNetworkUuids = getHeaderList(headers, "otherNetworkUuids")
                .stream()
                .map(UUID::fromString)
                .collect(Collectors.toList());
        List<String> contingencyListNames = getHeaderList(headers, "contingencyListNames");
        String receiver = (String) headers.get("receiver");
        String provider = (String) headers.get("provider");
        SecurityAnalysisParameters parameters;
        try {
            parameters = objectMapper.readValue(message.getPayload(), SecurityAnalysisParameters.class);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        UUID reportUuid = headers.containsKey(REPORT_UUID) ? UUID.fromString((String) headers.get(REPORT_UUID)) : null;
        SecurityAnalysisRunContext runContext = new SecurityAnalysisRunContext(networkUuid, variantId, otherNetworkUuids, contingencyListNames, receiver, provider, parameters, reportUuid);
        return new SecurityAnalysisResultContext(resultUuid, runContext);
    }
}
