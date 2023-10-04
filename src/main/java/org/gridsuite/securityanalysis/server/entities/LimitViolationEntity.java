package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.UUID;

@NoArgsConstructor
@Getter
@MappedSuperclass
public abstract class LimitViolationEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @ManyToOne
    private SecurityAnalysisResultEntity result;

    private String subjectId;

    private String subjectName;

    @Column(name = "limitValue")
    private double limit;

    private String limitName;

    @Enumerated(EnumType.STRING)
    private LimitViolationType limitType;

    private int acceptableDuration;

    private float limitReduction;

    @Column(name = "offendingValue")
    private double value;

    @Enumerated(EnumType.STRING)
    private Branch.Side side;

    public LimitViolationEntity(String subjectId, String subjectName, double limit, String limitName, LimitViolationType limitType, int acceptableDuration, float limitReduction, double value, Branch.Side side) {
        this.subjectId = subjectId;
        this.subjectName = subjectName;
        this.limit = limit;
        this.limitName = limitName;
        this.limitType = limitType;
        this.acceptableDuration = acceptableDuration;
        this.limitReduction = limitReduction;
        this.value = value;
        this.side = side;
    }
}
