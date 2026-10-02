package com.nids.threat3d.repository;

import com.nids.threat3d.model.NetworkFlow;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface NetworkFlowRepository extends JpaRepository<NetworkFlow, Long> {
    List<NetworkFlow> findTop100ByOrderByFlowStartDesc();
    List<NetworkFlow> findBySrcIpOrDstIp(String srcIp, String dstIp);
}
