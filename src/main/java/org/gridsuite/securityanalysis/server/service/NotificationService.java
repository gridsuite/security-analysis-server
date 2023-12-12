/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

/**
 * @author Seddik Yengui <seddik.yengui at rte-france.com>
 */

// Today we don't send notification inside @Transactional block. If this behavior change, we should use @PostCompletion to
// make sure that the notification is sent only when all the work inside @Transactional block is done.
@Service
public class NotificationService {
    public static final String RECEIVER_HEADER = "receiver";
    private static final String CATEGORY_BROKER_OUTPUT = NotificationService.class.getName() + ".output-broker-messages";
    private static final Logger OUTPUT_MESSAGE_LOGGER = LoggerFactory.getLogger(CATEGORY_BROKER_OUTPUT);
    public static final String CANCEL_MESSAGE = "Security analysis was canceled";
    public static final String FAIL_MESSAGE = "Security analysis has failed";
    public static final String RESULT_UUID_HEADER = "resultUuid";
    public static final String MESSAGE_HEADER = "message";
    public static final String NETWORK_UUID_HEADER = "networkUuid";
    public static final String VARIANT_ID_HEADER = "variantId";
    public static final String CONTINGENCY_LIST_NAMES_HEADER = "contingencyListNames";
    public static final String PROVIDER_HEADER = "provider";
    public static final String REPORT_UUID_HEADER = "reportUuid";
    public static final String REPORTER_ID_HEADER = "reporterId";
    public static final String REPORT_TYPE_HEADER = "reportType";
    public static final String HEADER_USER_ID = "userId";

    public static final int MSG_MAX_LENGTH = 256;

    @Autowired
    private StreamBridge publisher;

    private void sendMessage(Message<String> message, String bindingName) {
        OUTPUT_MESSAGE_LOGGER.debug("Sending message : {}", message);
        publisher.send(bindingName, message);
    }

    public void emitAnalysisResultsMessage(String resultUuid, String receiver) {
        sendMessage(MessageBuilder.withPayload("")
                                  .setHeader(RESULT_UUID_HEADER, resultUuid)
                                  .setHeader(RECEIVER_HEADER, receiver)
                                  .build(),
                "publishResult-out-0");
    }

    public void emitStopAnalysisMessage(String resultUuid, String receiver) {
        sendMessage(MessageBuilder.withPayload("")
                                  .setHeader(RESULT_UUID_HEADER, resultUuid)
                                  .setHeader(RECEIVER_HEADER, receiver)
                                  .setHeader(MESSAGE_HEADER, CANCEL_MESSAGE)
                                  .build(),
                "publishStopped-out-0");
    }

    public void emitFailAnalysisMessage(String resultUuid, String receiver, String causeMessage, String userId) {
        sendMessage(MessageBuilder.withPayload("")
                                  .setHeader(RESULT_UUID_HEADER, resultUuid)
                                  .setHeader(RECEIVER_HEADER, receiver)
                                  .setHeader(HEADER_USER_ID, userId)
                                  .setHeader(MESSAGE_HEADER, shortenMessage(FAIL_MESSAGE + " : " + causeMessage))
                                  .build(),
                "publishFailed-out-0");
    }

    public void emitRunAnalysisMessage(Message<String> message) {
        sendMessage(message, "publishRun-out-0");
    }

    public void emitCancelAnalysisMessage(Message<String> message) {
        sendMessage(message, "publishCancel-out-0");
    }

    // prevent the message from being too long for rabbitmq
    // the beginning and ending are both kept, it should make it easier to identify
    public String shortenMessage(String msg) {
        if (msg == null) {
            return msg;
        }

        return msg.length() > MSG_MAX_LENGTH ?
                msg.substring(0, MSG_MAX_LENGTH / 2) + " ... " + msg.substring(msg.length() - MSG_MAX_LENGTH / 2, msg.length() - 1)
                : msg;
    }
}
