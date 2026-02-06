package org.gridsuite.securityanalysis.server.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.*;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Service
public class DirectoryService {
    static final String DIRECTORY_API_VERSION = "v1";

    private static final String DELIMITER = "/";

    private String baseUri;

    private RestTemplate restTemplate;

    public void setDirectoryServiceBaseUri(String baseUri) {
        this.baseUri = baseUri;
    }

    public DirectoryService(
            @Value("${gridsuite.services.directory-server.base-uri:http://directory-server}") String baseUri,
            RestTemplate restTemplate) {
        this.baseUri = baseUri;
        this.restTemplate = restTemplate;
    }

    public String getContingenciesName(UUID contingenciesId) {
        Objects.requireNonNull(contingenciesId);

        URI path = UriComponentsBuilder
                .fromPath(DELIMITER + DIRECTORY_API_VERSION + "/elements/{elementUuid}")
                .buildAndExpand(contingenciesId)
                .toUri();

        try {
            ResponseEntity<Map<String, Object>> response =
                    restTemplate.exchange(
                            baseUri + path,
                            HttpMethod.GET,
                            null,
                            new ParameterizedTypeReference<>() { }
                    );

            Map<String, Object> responseBody = response.getBody();
            return responseBody != null ? (String) responseBody.get("elementName") : null;

        } catch (HttpClientErrorException.NotFound e) {
            return null;
        }
    }
}
