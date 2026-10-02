package com.nids.threat3d.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class RbacTestController {

    @GetMapping("/admin/status")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<Map<String, String>> getAdminStatus() {
        return ResponseEntity.ok(Map.of(
                "status", "AUTHORIZED",
                "message", "Welcome System Administrator. Full control access granted."
        ));
    }

    @GetMapping("/analyst/status")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_ANALYST')")
    public ResponseEntity<Map<String, String>> getAnalystStatus() {
        return ResponseEntity.ok(Map.of(
                "status", "AUTHORIZED",
                "message", "Welcome SOC Security Analyst. SOC threat analysis access granted."
        ));
    }
}
