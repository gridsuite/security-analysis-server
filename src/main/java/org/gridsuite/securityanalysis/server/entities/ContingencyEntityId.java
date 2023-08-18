package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Embeddable
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyEntityId implements Serializable {

    private UUID resultUuid;

    private String contingencyId;
}
