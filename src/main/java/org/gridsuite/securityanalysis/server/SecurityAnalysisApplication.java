/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.databind.Module;
import com.powsybl.contingency.json.ContingencyJsonModule;
import com.powsybl.security.json.SecurityAnalysisJsonModule;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@SpringBootApplication
public class SecurityAnalysisApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityAnalysisApplication.class, args);
    }

    @Bean
    public Module contingencyModule() {
        return new ContingencyJsonModule();
    }

    @Bean
    public Module securityAnalysisModule() {
        return new SecurityAnalysisJsonModule();
    }
}
