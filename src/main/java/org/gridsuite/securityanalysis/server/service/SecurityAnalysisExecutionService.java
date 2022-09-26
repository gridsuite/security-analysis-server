/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.service;

import com.powsybl.computation.ComputationManager;
import com.powsybl.computation.local.LocalComputationManager;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class SecurityAnalysisExecutionService {

    private ExecutorService executorService;

    @PostConstruct
    private void postConstruct() {
        executorService = Executors.newCachedThreadPool();
    }

    @PreDestroy
    private void preDestroy() {
        executorService.shutdown();
    }

    public ExecutorService getExecutorService() {
        return executorService;
    }

    public ComputationManager getLocalComputationManager() throws IOException {
        return new LocalComputationManager(getExecutorService());
    }
}
