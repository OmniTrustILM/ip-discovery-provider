package com.otilm.discovery.ip.api.v2;

import com.otilm.api.interfaces.connector.discovery.v2.DiscoveryOperationController;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryEvent;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStatusResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStreamRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryStopResponseDto;
import com.otilm.discovery.ip.ConnectorV2Api;
import com.otilm.discovery.ip.service.v2.DiscoveryRunService;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

/**
 * The run lifecycle on the wire. Thin on purpose: the sequencing, the idempotency and the bounds all live in
 * {@link DiscoveryRunService}, where they can be exercised without a servlet.
 */
@RestController
@ConnectorV2Api
public class DiscoveryOperationControllerImpl implements DiscoveryOperationController {

    private final DiscoveryRunService runService;

    public DiscoveryOperationControllerImpl(DiscoveryRunService runService) {
        this.runService = runService;
    }

    @Override
    public DiscoveryInitiateResponseDto initiate(DiscoveryInitiateRequestDto request) {
        return runService.initiate(request);
    }

    @Override
    public DiscoveryStatusResponseDto status(DiscoveryRunRequestDto request) {
        return runService.status(request);
    }

    @Override
    public DiscoveryResultsResponseDto results(DiscoveryDrainRequestDto request) {
        return runService.results(request);
    }

    /**
     * Not implemented, and not advertised either — {@code discoveryStreaming} is absent from the info response, so
     * Core has no reason to call this. Core has no stream client in any case.
     */
    @Override
    public Flux<DiscoveryEvent> stream(DiscoveryStreamRequestDto request) {
        throw new UnsupportedOperationException("This connector does not stream discovery events");
    }

    @Override
    public DiscoveryStopResponseDto stop(DiscoveryRunRequestDto request) {
        return runService.stop(request);
    }

    @Override
    public DiscoveryInitiateResponseDto resume(DiscoveryRunRequestDto request) {
        return runService.resume(request);
    }

    @Override
    public void cancel(DiscoveryRunRequestDto request) {
        runService.cancel(request);
    }
}
