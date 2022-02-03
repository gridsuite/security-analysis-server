package org.gridsuite.securityanalysis.server.repository;

import java.util.UUID;

import java.io.Serializable;

import javax.persistence.Embeddable;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@EqualsAndHashCode
@Embeddable
class ContingencyId implements Serializable {
    @Id
    private UUID resultUuid;

    @Id
    private String contingencyId;
}
