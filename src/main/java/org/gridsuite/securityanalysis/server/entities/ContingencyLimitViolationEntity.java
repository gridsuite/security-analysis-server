package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.*;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Entity
@Table(name = "contingency_limit_violation")
public class ContingencyLimitViolationEntity extends LimitViolationEntity {
    @ManyToOne
    private ContingencyEntity contingency;

    public ContingencyLimitViolationEntity(String subjectId, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        super(subjectId, subjectName, limit, limitName, limitType, acceptableDuration, limitReduction, value, side);
    }
}