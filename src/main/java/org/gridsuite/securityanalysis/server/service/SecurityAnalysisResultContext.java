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
import com.powsybl.ws.commons.computation.dto.ReportInfos;
import com.powsybl.ws.commons.computation.service.AbstractResultContext;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisPayload;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.MessageBuilder;

import java.io.UncheckedIOException;
import java.util.*;

import static com.powsybl.ws.commons.computation.service.NotificationService.*;
import static com.powsybl.ws.commons.computation.utils.MessageUtils.getNonNullHeader;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisResultContext extends AbstractResultContext<SecurityAnalysisRunContext> {

    public SecurityAnalysisResultContext(UUID resultUuid, SecurityAnalysisRunContext runContext) {
        super(resultUuid, runContext);
    }

    @Override
    public Message<String> toMessage(ObjectMapper objectMapper) {
        String payloadJson = "";
        if (objectMapper != null) {
            try {
                SecurityAnalysisPayload payload = new SecurityAnalysisPayload(getRunContext().getParameters(), getRunContext().getLimitReductions(), getRunContext().getContingencyListNames());
                payloadJson = objectMapper.writeValueAsString(payload);
            } catch (JsonProcessingException e) {
                throw new UncheckedIOException(e);
            }
        }
        return MessageBuilder.withPayload(payloadJson)
                .setHeader(RESULT_UUID_HEADER, getResultUuid().toString())
                .setHeader(NETWORK_UUID_HEADER, getRunContext().getNetworkUuid().toString())
                .setHeader(VARIANT_ID_HEADER, getRunContext().getVariantId())
                .setHeader(HEADER_RECEIVER, getRunContext().getReceiver())
                .setHeader(HEADER_PROVIDER, getRunContext().getProvider())
                .setHeader(HEADER_USER_ID, getRunContext().getUserId())
                .setHeader(REPORT_UUID_HEADER, getRunContext().getReportInfos().reportUuid() != null ? getRunContext().getReportInfos().reportUuid().toString() : null)
                .setHeader(REPORTER_ID_HEADER, getRunContext().getReportInfos().reporterId())
                .setHeader(REPORT_TYPE_HEADER, getRunContext().getReportInfos().computationType())
                .copyHeaders(getSpecificMsgHeaders(objectMapper))
                .build();
    }

    public static SecurityAnalysisResultContext fromMessage(Message<String> message, ObjectMapper objectMapper) {
        Objects.requireNonNull(message);
        MessageHeaders headers = message.getHeaders();
        UUID resultUuid = UUID.fromString(getNonNullHeader(headers, HEADER_RESULT_UUID));
        UUID networkUuid = UUID.fromString(getNonNullHeader(headers, NETWORK_UUID_HEADER));
        String variantId = (String) headers.get(VARIANT_ID_HEADER);
        String receiver = (String) headers.get(HEADER_RECEIVER);
        String provider = (String) headers.get(HEADER_PROVIDER);
        String userId = (String) headers.get(HEADER_USER_ID);
        List<List<Double>> limitReductions;
        SecurityAnalysisParameters parameters;
        List<String> contingencyListNames;
        try {
            SecurityAnalysisPayload payload = objectMapper.readValue(message.getPayload(), SecurityAnalysisPayload.class);
            parameters = payload.parameters();
            limitReductions = payload.limitReductions();
            contingencyListNames = payload.contingencyListNames();
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

}
