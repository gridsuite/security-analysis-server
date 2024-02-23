package org.gridsuite.securityanalysis.server.repositories.specifications;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

@Service
public class SubjectLimitViolationSpecificationBuilder extends AbstractCommonSpecificationBuilder<SubjectLimitViolationEntity> {
    public SubjectLimitViolationSpecificationBuilder() {
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(SubjectLimitViolationEntity.Fields.subjectId);
    }

    @Override
    public String getIdFieldName() {
        return SubjectLimitViolationEntity.Fields.id;
    }

    @Override
    public Specification<SubjectLimitViolationEntity> childrenNotEmpty() {
        return (contingency, cq, cb) -> cb.isNotEmpty(contingency.get(SubjectLimitViolationEntity.Fields.contingencyLimitViolations));
    }
}
