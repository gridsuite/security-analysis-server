/**
 * Copyright (c) 2021, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.PowsyblException;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageHeaders;
import org.springframework.messaging.support.MessageBuilder;

import java.util.Objects;
import java.util.UUID;

import static org.gridsuite.securityanalysis.server.computation.service.NotificationService.HEADER_RESULT_UUID;
import static org.gridsuite.securityanalysis.server.computation.service.NotificationService.HEADER_RECEIVER;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
public class SecurityAnalysisCancelContext {

    private final UUID resultUuid;

    private final String receiver;

    public SecurityAnalysisCancelContext(UUID resultUuid, String receiver) {
        this.resultUuid = Objects.requireNonNull(resultUuid);
        this.receiver = Objects.requireNonNull(receiver);
    }

    public UUID getResultUuid() {
        return resultUuid;
    }

    public String getReceiver() {
        return receiver;
    }

    private static String getNonNullHeader(MessageHeaders headers, String name) {
        String header = (String) headers.get(name);
        if (header == null) {
            throw new PowsyblException("Header '" + name + "' not found");
        }
        return header;
    }

    public static SecurityAnalysisCancelContext fromMessage(Message<String> message) {
        Objects.requireNonNull(message);
        MessageHeaders headers = message.getHeaders();
        UUID resultUuid = UUID.fromString(getNonNullHeader(headers, HEADER_RESULT_UUID));
        String receiver = (String) headers.get(HEADER_RECEIVER);
        return new SecurityAnalysisCancelContext(resultUuid, receiver);
    }

    public Message<String> toMessage() {
        return MessageBuilder.withPayload("")
                .setHeader(HEADER_RESULT_UUID, resultUuid.toString())
                .setHeader(HEADER_RECEIVER, receiver)
                .build();
    }
}
