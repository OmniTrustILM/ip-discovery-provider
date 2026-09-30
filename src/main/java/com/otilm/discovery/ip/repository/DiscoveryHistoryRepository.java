package com.otilm.discovery.ip.repository;

import com.otilm.discovery.ip.dao.DiscoveryHistory;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface DiscoveryHistoryRepository extends JpaRepository<DiscoveryHistory, Long> {
    Optional<DiscoveryHistory> findById(Long Id);

    Optional<DiscoveryHistory> findByUuid(String uuid);
}
