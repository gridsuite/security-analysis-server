/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface SecurityAnalysisResultRepository extends JpaRepository<SecurityAnalysisResultEntity, UUID> {
}
