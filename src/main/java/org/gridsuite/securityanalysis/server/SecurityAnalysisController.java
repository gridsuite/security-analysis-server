/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisResult;
import io.swagger.annotations.*;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RestController
@RequestMapping(value = "/" + SecurityAnalysisApi.API_VERSION)
@Api(value = "Security analysis server")
@ComponentScan(basePackageClasses = SecurityAnalysisService.class)
public class SecurityAnalysisController {

    private final SecurityAnalysisService service;

    public SecurityAnalysisController(SecurityAnalysisService service) {
        this.service = service;
    }

    @PostMapping(value = "/networks/{networkUuid}/run", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @ApiOperation(value = "run a security analysis on a network", produces = APPLICATION_JSON_VALUE, consumes = APPLICATION_JSON_VALUE)
    @ApiResponses(value = {@ApiResponse(code = 200, message = "The security analysis has been performed")})
    public ResponseEntity<SecurityAnalysisResult> run(@ApiParam(value = "Network UUID") @PathVariable("networkUuid") UUID networkUuid,
                                                      @ApiParam(value = "Other networks UUID (to merge with main one))") @RequestParam(name = "networkUuid", required = false) List<UUID> otherNetworkUuids,
                                                      @ApiParam(value = "Contingency list name") @RequestParam(name = "contingencyListName", required = false) List<String> contigencyListNames,
                                                      @RequestBody(required = false) SecurityAnalysisParameters parameters) {
        SecurityAnalysisParameters nonNullParameters = parameters != null ? parameters : new SecurityAnalysisParameters();
        List<UUID> nonNullOtherNetworkUuids = otherNetworkUuids != null ? otherNetworkUuids : Collections.emptyList();
        SecurityAnalysisResult result = service.run(networkUuid, nonNullOtherNetworkUuids, contigencyListNames, nonNullParameters);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(result);
    }
}
