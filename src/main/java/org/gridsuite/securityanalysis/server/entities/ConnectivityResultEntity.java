package org.gridsuite.securityanalysis.server.entities;

import com.powsybl.security.results.ConnectivityResult;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

import java.util.UUID;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldNameConstants;
import lombok.experimental.SuperBuilder;

@NoArgsConstructor
@SuperBuilder
@Getter
@Entity
@FieldNameConstants
@Table(name = "connectivity_result")
public class ConnectivityResultEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID uuid;

    private double disconnectedLoadActivePower;

    private double disconnectedGenerationActivePower;

    public static ConnectivityResultEntity toEntity(ConnectivityResult connectivityResult) {
        return ConnectivityResultEntity.builder()
            .disconnectedLoadActivePower(connectivityResult.getDisconnectedLoadActivePower())
            .disconnectedGenerationActivePower(connectivityResult.getDisconnectedGenerationActivePower())
            .build();
    }
}
