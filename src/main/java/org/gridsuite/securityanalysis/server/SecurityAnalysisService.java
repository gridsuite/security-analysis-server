/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.commons.PowsyblException;
import com.powsybl.computation.local.LocalComputationManager;
import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.mergingview.MergingView;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.xml.NetworkXml;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.security.SecurityAnalysis;
import com.powsybl.security.SecurityAnalysisFactory;
import com.powsybl.security.SecurityAnalysisParameters;
import com.powsybl.security.SecurityAnalysisResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@ComponentScan(basePackageClasses = {NetworkStoreService.class})
@Service
public class SecurityAnalysisService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityAnalysisService.class);

    private NetworkStoreService networkStoreService;

    private ActionsService actionsService;

    @Value("${securityAnalysisFactoryClass}")
    private String securityAnalysisFactoryClass;

    public SecurityAnalysisService(NetworkStoreService networkStoreService, ActionsService actionsService) {
        this.networkStoreService = Objects.requireNonNull(networkStoreService);
        this.actionsService = Objects.requireNonNull(actionsService);
    }

    private SecurityAnalysisFactory getSecurityAnalysisFactory() {
        try {
            return (SecurityAnalysisFactory) Class.forName(securityAnalysisFactoryClass).getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException | NoSuchMethodException | InvocationTargetException e) {
            throw new PowsyblException(e);
        }
    }

    private static String sanitizeParam(String param) {
        return param != null ? param.replaceAll("[\n|\r|\t]", "_") : null;
    }

    private Mono<Network> getNetwork(UUID networkUuid) {
        // FIXME to re-implement when network store service will be reactive
        return Mono.fromCallable(() -> {
            try {
                return networkStoreService.getNetwork(networkUuid, PreloadingStrategy.COLLECTION);
            } catch (PowsyblException e) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Network '" + networkUuid + "' not found");
            }
        });
    }

    private Mono<Network> getNetwork(UUID networkUuid, List<UUID> otherNetworkUuids) {
        Mono<Network> network = getNetwork(networkUuid);
        if (otherNetworkUuids.isEmpty()) {
            return network;
        } else {
            Mono<List<Network>> otherNetworks = Flux.fromIterable(otherNetworkUuids)
                    .flatMap(this::getNetwork)
                    .collectList();
            return Mono.zip(network, otherNetworks)
                    .map(t -> {
                        // creation of the merging view
                        List<Network> networks = new ArrayList<>();
                        networks.add(t.getT1());
                        networks.addAll(t.getT2());
                        MergingView mergingView = MergingView.create("merge", "iidm");
                        mergingView.merge(networks.toArray(new Network[0]));
                        return mergingView;
                    });
        }
    }

    public Mono<SecurityAnalysisResult> run(UUID networkUuid, List<UUID> otherNetworksUuid, List<String> contingencyListNames,
                                            SecurityAnalysisParameters parameters) {
        Objects.requireNonNull(networkUuid);
        Objects.requireNonNull(otherNetworksUuid);
        Objects.requireNonNull(contingencyListNames);
        Objects.requireNonNull(parameters);

        LOGGER.info("Run security analysis on contingency lists: {}", contingencyListNames.stream().map(SecurityAnalysisService::sanitizeParam).collect(Collectors.toList()));

        Mono<Network> network = getNetwork(networkUuid, otherNetworksUuid)
                .map(NetworkXml::copy); // FIXME workaround for bus/breaker view impl not yet implemented in network store

        Mono<List<Contingency>> contingencies = Flux.fromIterable(contingencyListNames)
                .flatMap(contingencyListName -> actionsService.getContingencyList(contingencyListName, networkUuid))
                .single();

        return Mono.zip(network, contingencies)
                .flatMap(tuple -> {
                    SecurityAnalysis securityAnalysis = getSecurityAnalysisFactory().create(tuple.getT1(), LocalComputationManager.getDefault(), 0);
                    CompletableFuture<SecurityAnalysisResult> result = securityAnalysis.run(VariantManagerConstants.INITIAL_VARIANT_ID, parameters, n -> tuple.getT2());
                    return Mono.fromCompletionStage(result);
                });
    }
}
