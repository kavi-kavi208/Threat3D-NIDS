package com.nids.threat3d.repository;

import com.nids.threat3d.model.SnortRule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SnortRuleRepository extends JpaRepository<SnortRule, String> {
    List<SnortRule> findByEnabledTrue();
    List<SnortRule> findByAttackCategory(String attackCategory);
}
