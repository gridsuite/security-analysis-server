/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.messaging.Message;
import org.springframework.stereotype.Service;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com
 */
@AllArgsConstructor
@Service
public class NotificationOnCaseService {
    @Getter private final StreamBridge publisher;
    @Getter private final String publishPrefix;

    @Autowired
    public NotificationOnCaseService(StreamBridge publisher) {
        this(publisher, "publish");
    }

    public void sendMessage(Message<? extends Object> message, String bindingName) {
        publisher.send(publishPrefix + bindingName, message);
    }
}
