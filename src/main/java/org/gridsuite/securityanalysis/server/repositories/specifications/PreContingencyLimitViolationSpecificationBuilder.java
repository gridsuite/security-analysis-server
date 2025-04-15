/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import com.powsybl.ws.commons.computation.dto.ResourceFilterDTO;
import com.powsybl.ws.commons.computation.utils.specification.SpecificationUtils;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */
@Service
public class PreContingencyLimitViolationSpecificationBuilder {
    public Specification<PreContingencyLimitViolationEntity> resultUuidEquals(UUID value) {
        return (contingency, cq, cb) -> cb.equal(contingency.get("result").get("id"), value);
    }

    public Specification<PreContingencyLimitViolationEntity> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        Specification<PreContingencyLimitViolationEntity> specification = Specification.where(resultUuidEquals(resultUuid));

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }
}
