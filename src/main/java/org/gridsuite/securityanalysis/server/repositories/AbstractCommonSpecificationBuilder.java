package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;
import java.util.UUID;

public abstract class AbstractCommonSpecificationBuilder<T> {
    public AbstractCommonSpecificationBuilder() {
    }

    public Specification<T> resultUuidEquals(UUID value) {
        return (contingency, cq, cb) -> cb.equal(contingency.get("result").get("id"), value);
    }

    public Specification<T> childrenNotEmpty() {
        return (contingency, cq, cb) -> cb.isNotEmpty(contingency.get("contingencyLimitViolations"));
    }

    public Specification<T> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        Specification<T> specification = SpecificationUtils.distinct();
        specification.and(Specification.where(resultUuidEquals(resultUuid)));
        specification = specification.and(childrenNotEmpty());

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public Specification<T> buildLimitViolationsSpecification(List<ResourceFilterDTO> resourceFilters) {
        Specification<T> specification = Specification.where(null);

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }

    public abstract boolean isParentFilter(ResourceFilterDTO filter);
}
