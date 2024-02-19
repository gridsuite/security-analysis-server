package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

import static java.util.function.Predicate.not;

@Service
public class ContingencySpecificationBuilder extends CommonSpecificationBuilder<ContingencyEntity> {
    private ContingencySpecificationBuilder() {
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ResourceFilterDTO.Column.CONTINGENCY_ID, ResourceFilterDTO.Column.STATUS).contains(filter.column());
    }
}
