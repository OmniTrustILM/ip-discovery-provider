package com.otilm.discovery.ip.repository;

import com.otilm.discovery.ip.dao.Certificate;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long>{
	List<Certificate> findAllByDiscoveryId(Long discoveryId, Pageable pagable);
	List<Certificate> findByDiscoveryId(Long discoveryId);
	List<Certificate> findByDiscoveryIdAndBase64Content(Long discoveryId, String base64Content);
	Optional<Certificate> findById(Long id);
}
