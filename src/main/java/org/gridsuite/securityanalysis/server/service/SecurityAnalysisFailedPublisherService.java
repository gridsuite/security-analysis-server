package org.gridsuite.securityanalysis.server.service;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.messaging.Message;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.stereotype.Service;

@Service
public class SecurityAnalysisFailedPublisherService {
    public static final String FAIL_MESSAGE = "Security analysis has failed";

    private static final String CATEGORY_BROKER_OUTPUT = SecurityAnalysisFailedPublisherService.class.getName() + ".output-broker-messages";

    private static final Logger LOGGER = LoggerFactory.getLogger(CATEGORY_BROKER_OUTPUT);

    @Autowired
    private StreamBridge failedMessagePublisher;

    public void publishFail(UUID resultUuid, String receiver, String causeMessage) {
        publish(resultUuid, receiver, FAIL_MESSAGE + " : " + causeMessage);
    }

    public void publish(UUID resultUuid, String receiver, String failMessage) {
        Message<String> message = MessageBuilder
                .withPayload("")
                .setHeader("resultUuid", resultUuid.toString())
                .setHeader("receiver", receiver)
                .setHeader("message", failMessage)
                .build();
        LOGGER.debug("Sending message : {}", message);
        failedMessagePublisher.send("publishFailed-out-0", message);
    }
}
