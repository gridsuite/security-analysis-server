/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@NoArgsConstructor
@Entity
@Table(name = "subject_limit_violation")
public class SubjectLimitViolationEntity {
    public SubjectLimitViolationEntity(String subjectId, String subjectName) {
        this.subjectId = subjectId;
        this.subjectName = subjectName;
    }

    @Id
    @GeneratedValue
    public UUID id;

    @Getter
    public String subjectId;

    private String subjectName;

    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    @Getter
    private SecurityAnalysisResultEntity result;

    @Getter
    @OneToMany(mappedBy = "subjectLimitViolation")
    List<ContingencyLimitViolationEntity> contingencyLimitViolations;

    public void addContingencyLimitViolation(ContingencyLimitViolationEntity contingencyLimitViolation) {
        if (this.contingencyLimitViolations == null) {
            this.contingencyLimitViolations = new ArrayList<>();
        }
        this.contingencyLimitViolations.add(contingencyLimitViolation);
    }
}
