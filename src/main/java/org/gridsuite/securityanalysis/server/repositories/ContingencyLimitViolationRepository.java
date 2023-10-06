package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface ContingencyLimitViolationRepository extends JpaRepository<ContingencyLimitViolationEntity, UUID> {
    List<ContingencyLimitViolationEntity> findByResultId(UUID resultuuid);
}
