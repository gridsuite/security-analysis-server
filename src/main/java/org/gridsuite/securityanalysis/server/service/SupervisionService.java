/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.springframework.stereotype.Service;

/**
 * @author Hugo Marcellin <hugo.marcelin at rte-france.com>
 */
@Service
public class SupervisionService {
    private final SecurityAnalysisResultRepository securityAnalysisResultRepository;

    public SupervisionService(SecurityAnalysisResultRepository securityAnalysisResultRepository) {
        this.securityAnalysisResultRepository = securityAnalysisResultRepository;
    }

    public Integer getResultsCount() {
        return (int) securityAnalysisResultRepository.count();
    }
}
