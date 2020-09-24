/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.commons.PowsyblException;
import com.powsybl.commons.exceptions.UncheckedClassNotFoundException;
import com.powsybl.commons.exceptions.UncheckedIllegalAccessException;
import com.powsybl.commons.exceptions.UncheckedInstantiationException;
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

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
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
        } catch (ClassNotFoundException e) {
            throw new UncheckedClassNotFoundException(e);
        } catch (IllegalAccessException e) {
            throw new UncheckedIllegalAccessException(e);
        } catch (InstantiationException e) {
            throw new UncheckedInstantiationException(e);
        } catch (NoSuchMethodException | InvocationTargetException e) {
            throw new PowsyblException(e);
        }
    }

    private static String sanitizeParam(String param) {
        return param != null ? param.replaceAll("[\n|\r|\t]", "_") : null;
    }

    private Network getNetwork(UUID networkUuid) {
        try {
            return networkStoreService.getNetwork(networkUuid, PreloadingStrategy.COLLECTION);
        } catch (PowsyblException e) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Network '" + networkUuid + "' not found");
        }
    }

    private Network getNetwork(UUID networkUuid, List<UUID> otherNetworksUuid) {
        if (otherNetworksUuid.isEmpty()) {
            return getNetwork(networkUuid);
        } else {
            // creation of the merging view
            MergingView merginvView = MergingView.create("merge", "iidm");
            List<Network> networks = new ArrayList<>(1 + otherNetworksUuid.size());
            networks.add(getNetwork(networkUuid));
            otherNetworksUuid.forEach(uuid -> networks.add(getNetwork(uuid)));
            merginvView.merge(networks.toArray(new Network[0]));
            return merginvView;
        }
    }

    public SecurityAnalysisResult run(UUID networkUuid, List<UUID> otherNetworksUuid, List<String> contingencyListNames,
                                      SecurityAnalysisParameters parameters) {
        Objects.requireNonNull(networkUuid);
        Objects.requireNonNull(otherNetworksUuid);
        Objects.requireNonNull(contingencyListNames);
        Objects.requireNonNull(parameters);

        LOGGER.info("Run security analysis on contingency lists: {}", contingencyListNames.stream().map(SecurityAnalysisService::sanitizeParam).collect(Collectors.toList()));

        Network network = getNetwork(networkUuid, otherNetworksUuid);

        List<Contingency> contingencies = contingencyListNames.stream()
                .flatMap(contingencyListName -> actionsService.getContingencyList(contingencyListName, networkUuid).stream())
                .collect(Collectors.toList());

        // FIXME workaround for bus/breaker view impl not yet implemented in network store
        network = NetworkXml.copy(network);

        SecurityAnalysis securityAnalysis = getSecurityAnalysisFactory().create(network, LocalComputationManager.getDefault(), 0);
        return securityAnalysis.run(VariantManagerConstants.INITIAL_VARIANT_ID, parameters, n -> contingencies).join();
    }
}
