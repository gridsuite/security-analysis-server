/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */

@Service
public class ContingencySpecificationBuilder extends AbstractCommonSpecificationBuilder<ContingencyEntity> {
    public boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ContingencyEntity.Fields.contingencyId, ContingencyEntity.Fields.status).contains(filter.column());
    }

    @Override
    public String getIdFieldName() {
        return ContingencyEntity.Fields.uuid;
    }

    @Override
    public Specification<ContingencyEntity> childrenNotEmpty() {
        return SpecificationUtils.isNotEmpty(ContingencyEntity.Fields.contingencyLimitViolations);
    }
}
