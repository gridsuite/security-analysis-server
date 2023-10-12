package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.ConstraintEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;

import java.util.UUID;

public interface ConstraintRepository extends PagingAndSortingRepository<ConstraintEntity, UUID> {
    Page<ConstraintEntity> findByResultIdOrderBySubjectId(UUID resultUuid, Pageable pageable);
}
