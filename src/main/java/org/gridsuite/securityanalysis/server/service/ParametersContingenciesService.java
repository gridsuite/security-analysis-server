package org.gridsuite.securityanalysis.server.service;

import org.gridsuite.securityanalysis.server.dto.ParametersContingenciesDTO;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Service
public class ParametersContingenciesService {

    private final DirectoryService directoryService;

    public ParametersContingenciesService(DirectoryService directoryService) {
        this.directoryService = directoryService;
    }

    public List<ParametersContingenciesDTO> toDTO(List<UUID> contingenciesIds) {
        return contingenciesIds == null ? null :
                contingenciesIds.stream()
                        .map(id -> new ParametersContingenciesDTO(id, getContingenciesName(id)))
                        .toList();
    }

    public List<UUID> toUUIDs(List<ParametersContingenciesDTO> contingenciesDTOs) {
        return contingenciesDTOs == null ? null :
                contingenciesDTOs.stream()
                        .map(ParametersContingenciesDTO::getId)
                        .toList();
    }

    private String getContingenciesName(UUID contingencyId) {
        return directoryService.getContingenciesName(contingencyId);
    }
}
