package com.nids.threat3d.repository;

import com.nids.threat3d.model.ThreatAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ThreatAlertRepository extends JpaRepository<ThreatAlert, Long> {
    List<ThreatAlert> findTop50ByOrderByTimestampDesc();
    List<ThreatAlert> findBySeverity(String severity);
    long countByMitigationStatus(String mitigationStatus);
}
