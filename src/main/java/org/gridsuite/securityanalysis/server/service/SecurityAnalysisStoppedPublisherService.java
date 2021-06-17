/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Service
public class SecurityAnalysisStoppedPublisherService {

    public static final String CANCEL_MESSAGE = "Security analysis was canceled";
    public static final String FAIL_MESSAGE = "Security analysis has failed";

    @Autowired
    private StreamBridge stoppedMessagePublisher;

    public void publishCancel(UUID resultUuid, String receiver) {
        publish(resultUuid, receiver, CANCEL_MESSAGE);
    }

    public void publishFail(UUID resultUuid, String receiver, String causeMessage) {
        publish(resultUuid, receiver, FAIL_MESSAGE + " : " + causeMessage);
    }

    public void publish(UUID resultUuid, String receiver, String stopMessage) {
        stoppedMessagePublisher.send("publishStopped-out-0", MessageBuilder
                .withPayload("")
                .setHeader("resultUuid", resultUuid.toString())
                .setHeader("receiver", receiver)
                .setHeader("message", stopMessage)
                .build());
    }
}
