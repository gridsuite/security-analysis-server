/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import com.powsybl.ws.commons.computation.dto.ResourceFilterDTO;
import com.powsybl.ws.commons.computation.utils.specification.SpecificationUtils;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Root;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */
@Service
public class SubjectLimitViolationSpecificationBuilder extends AbstractCommonSpecificationBuilder<SubjectLimitViolationEntity> {
    @Override
    public boolean isNotParentFilter(ResourceFilterDTO filter) {
        return !filter.column().equals(SubjectLimitViolationEntity.Fields.subjectId);
    }

    @Override
    public String getIdFieldName() {
        return SubjectLimitViolationEntity.Fields.id;
    }

    @Override
    public Path<UUID> getResultIdPath(Root<SubjectLimitViolationEntity> root) {
        return root.get(SubjectLimitViolationEntity.Fields.result).get(SecurityAnalysisResultEntity.Fields.id);
    }

    @Override
    public Specification<SubjectLimitViolationEntity> childrenNotEmpty() {
        return SpecificationUtils.isNotEmpty(SubjectLimitViolationEntity.Fields.contingencyLimitViolations);
    }

    @Override
    public Specification<SubjectLimitViolationEntity> addSpecificFilterWhenNoChildrenFilter() {
        return this.childrenNotEmpty();
    }
}
