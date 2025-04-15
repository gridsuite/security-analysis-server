/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.ws.commons.computation.dto.ResourceFilterDTO;
import com.powsybl.ws.commons.computation.utils.specification.AbstractCommonSpecificationBuilder;
import com.powsybl.ws.commons.computation.utils.specification.SpecificationUtils;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Root;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */
@Service
public class ContingencySpecificationBuilder extends AbstractCommonSpecificationBuilder<ContingencyEntity> {
    @Override
    public boolean isNotParentFilter(ResourceFilterDTO filter) {
        return !List.of(ContingencyEntity.Fields.contingencyId, ContingencyEntity.Fields.status).contains(filter.column());
    }

    @Override
    public String getIdFieldName() {
        return ContingencyEntity.Fields.uuid;
    }

    @Override
    public Path<UUID> getResultIdPath(Root<ContingencyEntity> root) {
        return root.get(ContingencyEntity.Fields.result).get(SecurityAnalysisResultEntity.Fields.id);
    }

    @Override
    public Specification<ContingencyEntity> addSpecificFilterWhenNoChildrenFilter() {
        return this.childrenNotEmpty().or(SpecificationUtils.notEqual(ContingencyEntity.Fields.status, LoadFlowResult.ComponentResult.Status.CONVERGED.name()));
    }

    @Override
    public Specification<ContingencyEntity> childrenNotEmpty() {
        return SpecificationUtils.isNotEmpty(ContingencyEntity.Fields.contingencyLimitViolations);
    }
}
