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

import java.util.UUID;
import java.util.stream.Collectors;

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
    public static final String OTHER_NETWORK_UUIDS_HEADER = "otherNetworkUuids";
    public static final String CONTINGENCY_LIST_NAMES_HEADER = "contingencyListNames";
    public static final String PROVIDER_HEADER = "provider";
    private static final String REPORT_UUID_HEADER = "reportUuid";

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

    public void emitFailAnalysisMessage(String resultUuid, String receiver, String causeMessage) {
        sendMessage(MessageBuilder.withPayload("")
                                  .setHeader(RESULT_UUID_HEADER, resultUuid)
                                  .setHeader(RECEIVER_HEADER, receiver)
                                  .setHeader(MESSAGE_HEADER, FAIL_MESSAGE + " : " + causeMessage)
                                  .build(),
                "publishFailed-out-0");
    }

    public void emitRunAnalysisMessage(String payload, String resultUuid, SecurityAnalysisRunContext runContext) {
        sendMessage(MessageBuilder.withPayload(payload)
                                  .setHeader(RESULT_UUID_HEADER, resultUuid)
                                  .setHeader(NETWORK_UUID_HEADER, runContext.getNetworkUuid().toString())
                                  .setHeader(VARIANT_ID_HEADER, runContext.getVariantId())
                                  .setHeader(OTHER_NETWORK_UUIDS_HEADER, runContext.getOtherNetworkUuids().stream()
                                         .map(UUID::toString).collect(Collectors.joining(",")))
                                  .setHeader(CONTINGENCY_LIST_NAMES_HEADER, String.join(",", runContext.getContingencyListNames()))
                                  .setHeader(RECEIVER_HEADER, runContext.getReceiver())
                                  .setHeader(PROVIDER_HEADER, runContext.getProvider())
                                  .setHeader(REPORT_UUID_HEADER, runContext.getReportUuid())
                                  .build(),
                "publishRun-out-0");
    }

    public void emitCancelAnalysisMessage(String resultUuid, String receiver) {
        sendMessage(MessageBuilder.withPayload("")
                                  .setHeader(RESULT_UUID_HEADER, resultUuid)
                                  .setHeader(RECEIVER_HEADER, receiver)
                                  .build(),
                "publishCancel-out-0");
    }
}
