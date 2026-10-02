package com.nids.threat3d.controller;

import com.nids.threat3d.model.NetworkNode;
import com.nids.threat3d.repository.NetworkNodeRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/telemetry")
public class NodeController {

    private final NetworkNodeRepository networkNodeRepository;

    public NodeController(NetworkNodeRepository networkNodeRepository) {
        this.networkNodeRepository = networkNodeRepository;
    }

    @GetMapping("/nodes")
    public ResponseEntity<List<NetworkNode>> getAllNodes() {
        return ResponseEntity.ok(networkNodeRepository.findAll());
    }
}
