/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.EmitterProcessor;
import reactor.core.publisher.Flux;

import java.io.UncheckedIOException;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisRunPublisher {

    private static final String CATEGORY_BROKER_OUTPUT = SecurityAnalysisRunPublisher.class.getName()
            + ".output-broker-messages";

    private ObjectMapper objectMapper;

    private final EmitterProcessor<Message<String>> runMessagePublisher = EmitterProcessor.create();

    public SecurityAnalysisRunPublisher(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    @Bean
    public Supplier<Flux<Message<String>>> publishRun() {
        return () -> runMessagePublisher.log(CATEGORY_BROKER_OUTPUT, Level.FINE);
    }

    public void publish(UUID resultUuid, SecurityAnalysisRunContext context) {
        String parametersJson;
        try {
            parametersJson = objectMapper.writeValueAsString(context.getParameters());
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
        runMessagePublisher.onNext(MessageBuilder
                .withPayload(parametersJson)
                .setHeader("resultUuid", resultUuid.toString())
                .setHeader("networkUuid", context.getNetworkUuid().toString())
                .setHeader("otherNetworkUuids", context.getOtherNetworkUuids().stream().map(UUID::toString).collect(Collectors.joining(",")))
                .setHeader("contingencyListNames", String.join(",", context.getContingencyListNames()))
                .build());
    }
}
