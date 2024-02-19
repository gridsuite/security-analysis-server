package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
public class PreContingencyLimitViolationSpecificationBuilder extends CommonSpecificationBuilder<PreContingencyLimitViolationEntity> {
    private PreContingencyLimitViolationSpecificationBuilder() {
    }

    @Override
    public Specification<PreContingencyLimitViolationEntity> buildSpecification(UUID resultUuid, List<ResourceFilterDTO> resourceFilters) {
        Specification<PreContingencyLimitViolationEntity> specification = Specification.where(resultUuidEquals(resultUuid));

        return SpecificationUtils.appendFiltersToSpecification(specification, resourceFilters);
    }


    public boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(ResourceFilterDTO.Column.SUBJECT_ID);
    }
}
