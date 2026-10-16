/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.security.interceptors.DefaultSecurityAnalysisInterceptor;
import com.powsybl.security.interceptors.SecurityAnalysisResultContext;
import com.powsybl.security.results.PostContingencyResult;
import org.gridsuite.computation.service.NotificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Interceptor that reports per-contingency progress during security analysis execution.
 * TODO Throttled to at most one message per second to avoid flooding the message broker.
 */
public class SecurityAnalysisProgressInterceptor extends DefaultSecurityAnalysisInterceptor {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisProgressInterceptor.class);
    private static final long THROTTLE_INTERVAL_MS = 1000L;

    private final NotificationService notificationService;
    private final UUID resultUuid;
    private final String receiver;
    private final String userId;
    private final int total;

    private final AtomicInteger counter = new AtomicInteger(0);
    private final AtomicLong lastSentMs = new AtomicLong(0L);

    public SecurityAnalysisProgressInterceptor(NotificationService notificationService,
                                               UUID resultUuid,
                                               String receiver,
                                               String userId,
                                               int total) {
        this.notificationService = notificationService;
        this.resultUuid = resultUuid;
        this.receiver = receiver;
        this.userId = userId;
        this.total = total;
    }

    @Override
    public void onPostContingencyResult(PostContingencyResult postContingencyResult, SecurityAnalysisResultContext context) {
        int current = counter.incrementAndGet();
        //TODO
        long now = System.currentTimeMillis();
        long last = lastSentMs.get();
        if (now - last >= THROTTLE_INTERVAL_MS && lastSentMs.compareAndSet(last, now)) {
            try {
                notificationService.sendProgressMessage(resultUuid, receiver, userId, current, total);
            } catch (Exception e) {
                LOGGER.warn("Failed to send security analysis progress notification", e);
            }
        }
    }
}
