/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories.specifications;

import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Root;
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
        return (root, cq, cb) -> cb.equal(getResultIdPath(root), value);
    }

    public Specification<T> uuidIn(List<UUID> uuids) {
        return (root, cq, cb) -> root.get(getIdFieldName()).in(uuids);
    }

    public Specification<T> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        List<ResourceFilterDTO> childrenResourceFilter = resourceFilters.stream().filter(this::isNotParentFilter).toList();
        // since sql joins generates duplicate results, we need to use distinct here
        Specification<T> specification = SpecificationUtils.distinct();
        // filter by resultUuid
        specification = specification.and(Specification.where(resultUuidEquals(resultUuid)));
        if (childrenResourceFilter.isEmpty()) {
            specification = specification.and(addSpecificFilterWhenNoChildrenFilter());
        } else {
            // needed here to filter main entities that would have empty collection when filters are applied
            specification = specification.and(childrenNotEmpty());
        }

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public Specification<T> buildLimitViolationsSpecification(List<UUID> uuids, List<ResourceFilterDTO> resourceFilters) {
        List<ResourceFilterDTO> childrenResourceFilter = resourceFilters.stream().filter(this::isNotParentFilter).toList();
        Specification<T> specification = Specification.where(uuidIn(uuids));

        return SpecificationUtils.appendFiltersToSpecification(specification, childrenResourceFilter);
    }

    public abstract Specification<T> childrenNotEmpty();

    public abstract boolean isNotParentFilter(ResourceFilterDTO filter);

    public abstract String getIdFieldName();

    public abstract Path<UUID> getResultIdPath(Root<T> root);

    public abstract Specification<T> addSpecificFilterWhenNoChildrenFilter();
}
