package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;
import java.util.UUID;

public abstract class CommonSpecificationBuilder <T> {
    public CommonSpecificationBuilder() {
    }

    public Specification<T> resultUuidEquals(UUID value) {
        return (contingency, cq, cb) -> cb.equal(contingency.get("result").get("id"), value);
    }

    public Specification<T> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        Specification<T> specification = SpecificationUtils.distinct();
        specification.and(Specification.where(resultUuidEquals(resultUuid)));

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public Specification<T> buildLimitViolationsSpecification(List<ResourceFilterDTO> resourceFilters) {
        Specification<T> specification = Specification.where(null);

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public abstract boolean isParentFilter(ResourceFilterDTO filter);
}
