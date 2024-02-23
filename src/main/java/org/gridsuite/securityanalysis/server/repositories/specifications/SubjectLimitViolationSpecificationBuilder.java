/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */

@Service
public class SubjectLimitViolationSpecificationBuilder extends AbstractCommonSpecificationBuilder<SubjectLimitViolationEntity> {
    public SubjectLimitViolationSpecificationBuilder() {
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(SubjectLimitViolationEntity.Fields.subjectId);
    }

    @Override
    public String getIdFieldName() {
        return SubjectLimitViolationEntity.Fields.id;
    }

    @Override
    public Specification<SubjectLimitViolationEntity> childrenNotEmpty() {
        return (contingency, cq, cb) -> cb.isNotEmpty(contingency.get(SubjectLimitViolationEntity.Fields.contingencyLimitViolations));
    }
}
