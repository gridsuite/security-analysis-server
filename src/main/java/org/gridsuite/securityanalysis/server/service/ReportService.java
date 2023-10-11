/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.reporter.Reporter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Service
public class ReportService {

    static final String REPORT_API_VERSION = "v1";

    private static final String DELIMITER = "/";

    public String baseUri;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    public ReportService(@Value("${gridsuite.services.report-server.base-uri:http://report-server/}") String baseUri) {
        this.baseUri = baseUri;
    }

    public void setReportServiceBaseUri(String baseUri) {
        this.baseUri = baseUri;
    }

    public void sendReport(UUID reportUuid, Reporter reporter) {
        Objects.requireNonNull(reportUuid);

        URI path = UriComponentsBuilder
            .fromPath(DELIMITER + REPORT_API_VERSION + "/reports/{reportUuid}")
            .build(reportUuid);

        restTemplate.put(baseUri + path, reporter);
    }
}
