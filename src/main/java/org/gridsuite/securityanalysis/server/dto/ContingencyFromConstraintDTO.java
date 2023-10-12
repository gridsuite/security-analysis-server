/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;

import java.util.List;
import java.util.stream.Collectors;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyFromConstraintDTO {
    private String contingencyId;
    private String computationStatus;
    private LimitViolationType limitType;
    private String limitName;
    private Branch.Side side;
    private int acceptableDuration;
    private double limit;
    private double value;
    private List<ContingencyElementDTO> elements;

    public static ContingencyFromConstraintDTO toDto(ContingencyLimitViolationEntity limitViolation) {
        ContingencyEntity contingency = limitViolation.getContingency();
        return new ContingencyFromConstraintDTO(
            contingency.getContingencyId(),
            contingency.getStatus(),
            limitViolation.getLimitType(),
            limitViolation.getLimitName(),
            limitViolation.getSide(),
            limitViolation.getAcceptableDuration(),
            limitViolation.getLimit(),
            limitViolation.getValue(),
            contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).collect(Collectors.toList())
        );
    }
}
