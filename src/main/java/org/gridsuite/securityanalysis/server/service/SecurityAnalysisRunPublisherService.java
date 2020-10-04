/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import reactor.core.publisher.EmitterProcessor;
import reactor.core.publisher.Flux;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.logging.Level;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class SecurityAnalysisRunPublisherService {

    private static final String CATEGORY_BROKER_OUTPUT = SecurityAnalysisRunPublisherService.class.getName()
            + ".output-broker-messages";

    private ObjectMapper objectMapper;

    private final EmitterProcessor<Message<String>> runMessagePublisher = EmitterProcessor.create();

    public SecurityAnalysisRunPublisherService(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    @Bean
    public Supplier<Flux<Message<String>>> publishRun() {
        return () -> runMessagePublisher.log(CATEGORY_BROKER_OUTPUT, Level.FINE);
    }

    public void publish(SecurityAnalysisResultContext resultContext) {
        Objects.requireNonNull(resultContext);
        runMessagePublisher.onNext(resultContext.toMessage(objectMapper));
    }
}
