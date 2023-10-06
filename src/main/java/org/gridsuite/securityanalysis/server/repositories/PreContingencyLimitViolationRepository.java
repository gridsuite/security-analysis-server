package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PreContingencyLimitViolationRepository extends JpaRepository<PreContingencyLimitViolationEntity, UUID> {
    List<PreContingencyLimitViolationEntity> findByResultId(UUID resultUuid);
}
