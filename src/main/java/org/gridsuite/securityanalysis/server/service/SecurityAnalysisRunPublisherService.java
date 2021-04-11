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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.util.Objects;
import java.util.concurrent.locks.LockSupport;
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


    private final Sinks.Many runMessagePublisher = Sinks.many().multicast().onBackpressureBuffer();

    public SecurityAnalysisRunPublisherService(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper);
    }

    @Bean
    public Supplier<Flux<Message<String>>> publishRun() {
        return () -> runMessagePublisher.asFlux().log(CATEGORY_BROKER_OUTPUT, Level.FINE);
    }

    public void publish(SecurityAnalysisResultContext resultContext) {
        Objects.requireNonNull(resultContext);
        while (runMessagePublisher.tryEmitNext(resultContext.toMessage(objectMapper)).isFailure()) {
            LockSupport.parkNanos(10);
        }
    }
}
