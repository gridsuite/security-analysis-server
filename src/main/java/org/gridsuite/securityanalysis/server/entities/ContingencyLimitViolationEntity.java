package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@Entity
@Getter
@Table(name = "contingency_limit_violation")
public class ContingencyLimitViolationEntity extends AbstractLimitViolationEntity {
    @ManyToOne(fetch = FetchType.LAZY)
    @Setter
    private ContingencyEntity contingency;

    public ContingencyLimitViolationEntity(ConstraintEntity constraint, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        super(constraint, subjectName, limit, limitName, limitType, acceptableDuration, limitReduction, value, side);
        if (constraint != null) {
            constraint.addContingencyLimitViolation(this);
        }
    }
}
