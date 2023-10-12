/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.Entity;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@NoArgsConstructor
@Getter
@Entity
@Table(name = "pre_contingency_limit_violation")
public class PreContingencyLimitViolationEntity extends AbstractLimitViolationEntity {

    @ManyToOne
    @Setter
    SecurityAnalysisResultEntity result;

    public PreContingencyLimitViolationEntity(ConstraintEntity constraint, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        super(constraint, subjectName, limit, limitName, limitType, acceptableDuration, limitReduction, value, side);
    }
}
