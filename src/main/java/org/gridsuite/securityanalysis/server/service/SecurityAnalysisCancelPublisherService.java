/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import org.springframework.context.annotation.Bean;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;
import reactor.core.publisher.EmitterProcessor;
import reactor.core.publisher.Flux;

import java.util.Objects;
import java.util.function.Supplier;
import java.util.logging.Level;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisCancelPublisherService {

    private static final String CATEGORY_BROKER_OUTPUT = SecurityAnalysisCancelPublisherService.class.getName()
            + ".output-broker-messages";

    private final EmitterProcessor<Message<String>> cancelMessagePublisher = EmitterProcessor.create();

    @Bean
    public Supplier<Flux<Message<String>>> publishCancel() {
        return () -> cancelMessagePublisher.log(CATEGORY_BROKER_OUTPUT, Level.FINE);
    }

    public void publish(SecurityAnalysisCancelContext cancelContext) {
        Objects.requireNonNull(cancelContext);
        cancelMessagePublisher.onNext(cancelContext.toMessage());
    }
}
