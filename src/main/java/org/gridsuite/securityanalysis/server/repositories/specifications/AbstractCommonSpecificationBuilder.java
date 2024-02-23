/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;
import java.util.UUID;
/**
 * @author Kevin LE SAULNIER <kevin.lesaulnier@rte-france.com>
 */

public abstract class AbstractCommonSpecificationBuilder<T> {
    AbstractCommonSpecificationBuilder() {
    }

    public Specification<T> resultUuidEquals(UUID value) {
        return (contingency, cq, cb) -> cb.equal(contingency.get("result").get("id"), value);
    }

    public Specification<T> uuidIn(List<UUID> uuids) {
        return (contingency, cq, cb) -> contingency.get(getIdFieldName()).in(uuids);
    }

    public Specification<T> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        Specification<T> specification = SpecificationUtils.distinct();
        specification.and(Specification.where(resultUuidEquals(resultUuid)));
        specification = specification.and(childrenNotEmpty());

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public Specification<T> buildLimitViolationsSpecification(List<UUID> uuids, List<ResourceFilterDTO> resourceFilters) {
        Specification<T> specification = Specification.where(uuidIn(uuids));

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public abstract Specification<T> childrenNotEmpty();

    public abstract boolean isParentFilter(ResourceFilterDTO filter);

    public abstract String getIdFieldName();
}
