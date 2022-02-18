/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import java.util.List;
import java.util.UUID;

import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Repository
public interface ContingencyRepository extends JpaRepository<ContingencyEntity, UUID> {

    List<ContingencyEntity> findByResultUuid(UUID resultUuid);

    void deleteByResultUuid(UUID resultUuid);
}
