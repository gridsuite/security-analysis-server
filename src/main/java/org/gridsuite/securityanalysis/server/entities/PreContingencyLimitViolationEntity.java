package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.Embeddable;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
@Entity
@Table(name = "pre_contingency_limit_violation")
public class PreContingencyLimitViolationEntity extends AbstractLimitViolationEntity {

    public PreContingencyLimitViolationEntity(String subjectId, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        super(subjectId, subjectName, limit, limitName, limitType, acceptableDuration, limitReduction, value, side);
    }
}
