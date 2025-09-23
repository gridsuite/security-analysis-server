/**
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Network;
import com.powsybl.security.LimitViolation;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
class ContingencyLimitViolationTest extends AbstractLimitViolationTest<ContingencyLimitViolationEntity> {

    @Override
    protected ContingencyLimitViolationEntity createLimitViolationEntity(Network network, LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolationEntity) {
        return ContingencyLimitViolationEntity.toEntity(network, limitViolation, subjectLimitViolationEntity);
    }
}
