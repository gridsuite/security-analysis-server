/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.security.SecurityAnalysisParameters;
import org.gridsuite.securityanalysis.server.computation.dto.ReportInfos;
import org.gridsuite.securityanalysis.server.computation.service.AbstractResultContext;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;

import java.io.UncheckedIOException;
import java.util.*;
import java.util.stream.Collectors;

import static org.gridsuite.securityanalysis.server.computation.service.NotificationService.*;
import static org.gridsuite.securityanalysis.server.computation.utils.MessageUtils.getNonNullHeader;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisResultContext extends AbstractResultContext<SecurityAnalysisRunContext> {
    public static final String CONTINGENCY_LIST_NAMES_HEADER = "contingencyListNames";
    public static final String LIMIT_REDUCTIONS_HEADER = "limitReductions";

    public SecurityAnalysisResultContext(UUID resultUuid, SecurityAnalysisRunContext runContext) {
        super(resultUuid, runContext);
    }

    private static List<String> getHeaderList(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null || header.isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.asList(header.split(","));
    }

    public static SecurityAnalysisResultContext fromMessage(Message<String> message, ObjectMapper objectMapper) {
        Objects.requireNonNull(message);
        MessageHeaders headers = message.getHeaders();
        UUID resultUuid = UUID.fromString(getNonNullHeader(headers, HEADER_RESULT_UUID));
        UUID networkUuid = UUID.fromString(getNonNullHeader(headers, NETWORK_UUID_HEADER));
        String variantId = (String) headers.get(VARIANT_ID_HEADER);
        List<String> contingencyListNames = getHeaderList(headers, CONTINGENCY_LIST_NAMES_HEADER);
        String receiver = (String) headers.get(HEADER_RECEIVER);
        String provider = (String) headers.get(HEADER_PROVIDER);
        String userId = (String) headers.get(HEADER_USER_ID);
        List<List<Double>> limitReductions = getLimitReductionsFromHeader(headers, LIMIT_REDUCTIONS_HEADER);
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
                userId,
                limitReductions
        );
        return new SecurityAnalysisResultContext(resultUuid, runContext);
    }

    private static List<List<Double>> getLimitReductionsFromHeader(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null || header.isEmpty()) {
            return Collections.emptyList();
        }

        return Arrays.stream(header.split(";"))
                .map(outer -> Arrays.stream(outer.split(","))
                        .map(inner -> Double.parseDouble(inner.trim()))
                        .collect(Collectors.toList()))
                .collect(Collectors.toList());
    }

    @Override
    protected Map<String, String> getSpecificMsgHeaders() {
        return Map.of(
                CONTINGENCY_LIST_NAMES_HEADER, String.join(",", runContext.getContingencyListNames()),
                LIMIT_REDUCTIONS_HEADER, formatLimitReductionsToHeader(runContext.getLimitReductions()));
    }

    private static String formatLimitReductionsToHeader(List<List<Double>> limitReductions) {
        return limitReductions.stream()
                .map(innerList -> innerList.stream()
                        .map(String::valueOf)
                        .collect(Collectors.joining(",")))
                .collect(Collectors.joining(";"));
    }
}
