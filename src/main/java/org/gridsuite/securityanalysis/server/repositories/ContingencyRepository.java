package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ContingencyRepository extends JpaRepository<ContingencyEntity, UUID> {
    List<ContingencyEntity> findByResultIdOrderByContingencyId(UUID resultUuid);
}
