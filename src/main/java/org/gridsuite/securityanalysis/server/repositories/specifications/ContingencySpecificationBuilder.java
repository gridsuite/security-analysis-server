package org.gridsuite.securityanalysis.server.repositories.specifications;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ContingencySpecificationBuilder extends AbstractCommonSpecificationBuilder<ContingencyEntity> {
    public ContingencySpecificationBuilder() {
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ContingencyEntity.Fields.contingencyId, ContingencyEntity.Fields.status).contains(filter.column());
    }

    @Override
    public String getIdFieldName() {
        return ContingencyEntity.Fields.uuid;
    }

    @Override
    public Specification<ContingencyEntity> childrenNotEmpty() {
        return (contingency, cq, cb) -> cb.isNotEmpty(contingency.get(ContingencyEntity.Fields.contingencyLimitViolations));
    }
}
