/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repository;

import java.util.UUID;

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Embeddable;
import javax.persistence.Entity;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@IdClass(LimitViolationEntity.ID.class)
@Table(name = "limitViolation")
public class LimitViolationEntity implements Serializable {

    /**
     * @author Laurent Garnier <laurent.garnier at rte-france.com>
     */
    @NoArgsConstructor
    @Getter
    @Embeddable
    public static class ID implements Serializable {

        private UUID resultUuid;

        @Enumerated(EnumType.STRING)
        private LimitViolationType limitType;

        private String contingencyId;

        private String subjectId;
    }

    @Id
    private UUID resultUuid;

    @Id
    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    @Id
    private String contingencyId;

    @Id
    private String subjectId;

    private String subjectName;

    @Column(name = "limitValue")
    private double limit;

    private String limitName;

    private int acceptableDuration;

    private float limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private Branch.Side side;
}
