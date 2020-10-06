/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repository;

import com.powsybl.security.LimitViolationType;
import org.springframework.data.cassandra.repository.ReactiveCassandraRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Set;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Repository
public interface LimitViolationRepository extends ReactiveCassandraRepository<LimitViolationEntity, UUID> {

    Flux<LimitViolationEntity> findByResultUuid(UUID resultUuid);

    Flux<LimitViolationEntity> findByResultUuidAndLimitTypeIn(UUID resultUuid, Set<LimitViolationType> limitTypes);

    Mono<Void> deleteByResultUuid(UUID resultUuid);
}
