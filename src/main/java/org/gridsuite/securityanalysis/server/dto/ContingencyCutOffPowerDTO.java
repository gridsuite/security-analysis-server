/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Ghazwa Rehili <ghazwa.rehili at rte-france.com>
 */
public record ContingencyCutOffPowerDTO(
        String contingencyId,
        String status,
        ConnectivityResultDTO connectivityResult
) {
    public static ContingencyCutOffPowerDTO toDto(ContingencyEntity entity) {
        return new ContingencyCutOffPowerDTO(
                entity.getContingencyId(),
                entity.getStatus(),
                ConnectivityResultDTO.toDto(entity.getConnectivityResult())
        );
    }

    public List<List<String>> toCsvRows(Map<String, String> translations, String language) {
        List<String> csvRow = new ArrayList<>();
        csvRow.add(contingencyId);
        csvRow.add(CsvExportUtils.translate(status, translations));
        if (connectivityResult != null) {
            csvRow.add(CsvExportUtils.convertDoubleToLocale(connectivityResult.getDisconnectedLoadActivePower(), language));
            csvRow.add(CsvExportUtils.convertDoubleToLocale(connectivityResult.getDisconnectedGenerationActivePower(), language));
        }
        return List.of(csvRow);
    }
}
