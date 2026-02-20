/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Getter;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Getter
public class SecurityAnalysisCaseContext {
    public final UUID caseUuid;
    public final UUID executionUuid;
    public final List<String> contigencyListNames;
    public final UUID parametersUuid;
    public final UUID loadFlowParametersUuid;

    public SecurityAnalysisCaseContext(UUID caseUuid, UUID executionUuid, List<String> contigencyListNames, UUID parametersUuid, UUID loadFlowParametersUuid) {
        this.caseUuid = caseUuid;
        this.executionUuid = executionUuid;
        this.contigencyListNames = contigencyListNames;
        this.parametersUuid = parametersUuid;
        this.loadFlowParametersUuid = loadFlowParametersUuid;
    }

    public static SecurityAnalysisCaseContext fromMessage(Message<String> message, ObjectMapper objectMapper) {
        Objects.requireNonNull(message);
        SecurityAnalysisCaseContext context;
        try {
            context = objectMapper.readValue(message.getPayload(), SecurityAnalysisCaseContext.class);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        return context;
    }

    public Message<String> toMessage(ObjectMapper objectMapper) {
        String json;
        try {
            json = objectMapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        return MessageBuilder.withPayload(json).build();
    }
}
