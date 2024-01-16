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
import org.gridsuite.securityanalysis.server.dto.ReportInfos;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.MessageBuilder;

import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.gridsuite.securityanalysis.server.service.NotificationService.*;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisResultContext {

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
        UUID resultUuid = UUID.fromString(getNonNullHeader(headers, RESULT_UUID_HEADER));
        UUID networkUuid = UUID.fromString(getNonNullHeader(headers, NETWORK_UUID_HEADER));
        String variantId = (String) headers.get(VARIANT_ID_HEADER);
        List<String> contingencyListNames = getHeaderList(headers, CONTINGENCY_LIST_NAMES_HEADER);
        String receiver = (String) headers.get(RECEIVER_HEADER);
        String provider = (String) headers.get(PROVIDER_HEADER);
        String userId = (String) headers.get(HEADER_USER_ID);
        SecurityAnalysisParameters parameters;
        try {
            parameters = objectMapper.readValue(message.getPayload(), SecurityAnalysisParameters.class);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        UUID reportUuid = headers.containsKey(REPORT_UUID_HEADER) ? UUID.fromString((String) headers.get(REPORT_UUID_HEADER)) : null;
        String reporterId = headers.containsKey(REPORTER_ID_HEADER) ? (String) headers.get(REPORTER_ID_HEADER) : null;
        String reportType = headers.containsKey(REPORT_TYPE_HEADER) ? (String) headers.get(REPORT_TYPE_HEADER) : null;
        SecurityAnalysisRunContext runContext = new SecurityAnalysisRunContext(
                networkUuid,
                variantId,
                contingencyListNames,
                receiver,
                provider,
                parameters,
                new ReportInfos(reportUuid, reporterId, reportType),
                userId
        );
        return new SecurityAnalysisResultContext(resultUuid, runContext);
    }

    public Message<String> toMessage(ObjectMapper objectMapper) {
        String parametersJson;
        try {
            parametersJson = objectMapper.writeValueAsString(runContext.getParameters());
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        return MessageBuilder.withPayload(parametersJson)
                .setHeader(RESULT_UUID_HEADER, resultUuid.toString())
                .setHeader(NETWORK_UUID_HEADER, runContext.getNetworkUuid().toString())
                .setHeader(VARIANT_ID_HEADER, runContext.getVariantId())
                .setHeader(CONTINGENCY_LIST_NAMES_HEADER, String.join(",", runContext.getContingencyListNames()))
                .setHeader(RECEIVER_HEADER, runContext.getReceiver())
                .setHeader(HEADER_USER_ID, runContext.getUserId())
                .setHeader(PROVIDER_HEADER, runContext.getProvider())
                .setHeader(REPORT_UUID_HEADER, runContext.getReportUuid())
                .setHeader(REPORTER_ID_HEADER, runContext.getReporterId())
                .setHeader(REPORT_TYPE_HEADER, runContext.getReportType())
                .build();
    }
}
