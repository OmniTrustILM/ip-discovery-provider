package com.otilm.discovery.ip.repository;

import com.otilm.discovery.ip.dao.Certificate;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long>{
	List<Certificate> findAllByDiscoveryId(Long discoveryId, Pageable pagable);
	List<Certificate> findByDiscoveryId(Long discoveryId);
	List<Certificate> findByDiscoveryIdAndBase64Content(Long discoveryId, String base64Content);
	Optional<Certificate> findById(Long id);

	long countByDiscoveryId(Long discoveryId);

	/**
	 * Written out rather than derived: a derived {@code deleteBy} loads every matching entity and removes them one at a
	 * time, which is the cost this replaces. {@code clearAutomatically} is required because a bulk statement bypasses
	 * the persistence context, so without it a read in the same transaction would still see the deleted rows.
	 */
	@Modifying(clearAutomatically = true)
	@Query("DELETE FROM Certificate c WHERE c.discoveryId = :discoveryId")
	int deleteAllByDiscoveryId(@Param("discoveryId") Long discoveryId);
}
