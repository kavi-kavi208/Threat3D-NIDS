package com.nids.threat3d.repository;

import com.nids.threat3d.model.NetworkNode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface NetworkNodeRepository extends JpaRepository<NetworkNode, String> {
    Optional<NetworkNode> findByIpAddress(String ipAddress);
    List<NetworkNode> findByStatus(String status);
    List<NetworkNode> findByNodeType(String nodeType);
}
