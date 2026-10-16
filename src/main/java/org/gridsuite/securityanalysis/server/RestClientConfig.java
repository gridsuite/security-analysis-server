package org.gridsuite.securityanalysis.server;

/*
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

import com.fasterxml.jackson.databind.*;
import com.powsybl.commons.report.ReportNodeDeserializer;
import com.powsybl.commons.report.ReportNodeJsonModule;
import com.powsybl.contingency.json.ContingencyJsonModule;
import com.powsybl.loadflow.json.LoadFlowParametersJsonModule;
import com.powsybl.security.json.SecurityAnalysisJsonModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean
    public RestClient restClient(RestClient.Builder builder) {
        return builder.messageConverters(httpMessageConverters -> {
            //find and replace Jackson message converter with our own
            for (int i = 0; i < httpMessageConverters.size(); i++) {
                final HttpMessageConverter<?> httpMessageConverter = httpMessageConverters.get(i);
                if (httpMessageConverter instanceof MappingJackson2HttpMessageConverter) {
                    httpMessageConverters.set(i, mappingJackson2HttpMessageConverter());
                }
            }
        }).build();
    }

    public MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter() {
        MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
        converter.setObjectMapper(objectMapper());
        return converter;
    }

    private ObjectMapper createObjectMapper() {
        ObjectMapper objectMapper = Jackson2ObjectMapperBuilder.json()
            .featuresToEnable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS).build();
        objectMapper.registerModule(new ContingencyJsonModule());
        objectMapper.registerModule(new SecurityAnalysisJsonModule());
        objectMapper.registerModule(new LoadFlowParametersJsonModule());
        objectMapper.registerModule(new ReportNodeJsonModule());
        objectMapper.setInjectableValues(new InjectableValues.Std().addValue(ReportNodeDeserializer.DICTIONARY_VALUE_ID, null));
        return objectMapper;
    }

    @Bean
    public ObjectMapper objectMapper() {
        return createObjectMapper();
    }

}
