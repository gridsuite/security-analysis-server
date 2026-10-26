/**
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.contingency.violations.LimitViolation;
import com.powsybl.iidm.network.Network;
import org.gridsuite.computation.dto.securityanalysis.EnrichedLimitViolationDTO;
import org.gridsuite.computation.utils.ComputationResultUtils;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;

/**
 * @author Caroline Jeandat <caroline.jeandat at rte-france.com>
 */
class PreContingencyLimitViolationTest extends AbstractLimitViolationTest<PreContingencyLimitViolationEntity> {

    @Override
    protected PreContingencyLimitViolationEntity createLimitViolationEntity(Network network, LimitViolation limitViolation, SubjectLimitViolationEntity subjectLimitViolationEntity) {
        EnrichedLimitViolationDTO enrichment = EnrichedLimitViolationDTO.builder()
            .patlLimit(ComputationResultUtils.getPatlLimit(limitViolation, network))
            .patlLoading(ComputationResultUtils.computeLoading(limitViolation, ComputationResultUtils.getPatlLimit(limitViolation, network)))
            .nextLimitName(ComputationResultUtils.getNextLimitName(limitViolation, network))
            .locationId(ComputationResultUtils.getViolationLocationId(limitViolation, network))
            .acceptableDuration(ComputationResultUtils.calculateActualOverloadDuration(limitViolation, network))
            .build();
        return PreContingencyLimitViolationEntity.toEntity(limitViolation, subjectLimitViolationEntity, enrichment);
    }
}
