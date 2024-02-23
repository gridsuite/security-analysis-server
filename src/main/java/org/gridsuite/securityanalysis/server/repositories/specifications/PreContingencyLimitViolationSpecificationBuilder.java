/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */

@Service
public class PreContingencyLimitViolationSpecificationBuilder extends AbstractCommonSpecificationBuilder<PreContingencyLimitViolationEntity> {
    public PreContingencyLimitViolationSpecificationBuilder() {
    }

    @Override
    public Specification<PreContingencyLimitViolationEntity> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        Specification<PreContingencyLimitViolationEntity> specification = Specification.where(resultUuidEquals(resultUuid));

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(SubjectLimitViolationEntity.Fields.subjectId);
    }

    @Override
    public String getIdFieldName() {
        return AbstractLimitViolationEntity.Fields.id;
    }
}
