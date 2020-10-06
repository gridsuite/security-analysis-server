/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.PowsyblException;
import com.powsybl.security.SecurityAnalysisFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Service;

import java.lang.reflect.InvocationTargetException;
import java.util.Objects;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
@PropertySource("classpath:application.yaml")
public class SecurityAnalysisConfigService {

    @Value("${securityAnalysisFactoryClass}")
    private String securityAnalysisFactoryClass;

    public void setSecurityAnalysisFactoryClass(String securityAnalysisFactoryClass) {
        this.securityAnalysisFactoryClass = Objects.requireNonNull(securityAnalysisFactoryClass);
    }

    public SecurityAnalysisFactory getSecurityAnalysisFactory() {
        try {
            return (SecurityAnalysisFactory) Class.forName(securityAnalysisFactoryClass).getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | InvocationTargetException e) {
            throw new PowsyblException(e);
        }
    }
}
