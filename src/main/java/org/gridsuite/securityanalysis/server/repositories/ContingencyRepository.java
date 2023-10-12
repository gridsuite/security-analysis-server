package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ContingencyRepository extends PagingAndSortingRepository<ContingencyEntity, UUID> {
    Page<ContingencyEntity> findByResultId(UUID resultUuid, Pageable pageable);
}
