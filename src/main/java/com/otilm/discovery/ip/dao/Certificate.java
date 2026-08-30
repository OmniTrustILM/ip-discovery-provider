package com.otilm.discovery.ip.dao;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.connector.discovery.DiscoveryProviderCertificateDataDto;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.discovery.ip.util.DtoMapper;
import jakarta.persistence.*;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;


@Entity
@Table(name = "ip_discovery_certificate")
public class Certificate extends Audited implements Serializable, DtoMapper<DiscoveryProviderCertificateDataDto> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3048734620156664554L;

	@Id
	@Column(name= "id")
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "ip_discovery_certificate_seq")
	@SequenceGenerator(name = "ip_discovery_certificate_seq", sequenceName = "ip_discovery_certificate_id_seq", allocationSize = 1)
	private Long id;
	
	@Column(name="base64content", length = 1000000)
	private String base64Content;

	@Column(name="uuid")
	private String uuid;
	
	@Column(name="discovery_id")
	private Long discoveryId;
	
	@Column(name = "meta")
	private String meta;
	
	@Override
	public DiscoveryProviderCertificateDataDto mapToDto() {
		DiscoveryProviderCertificateDataDto dto = new DiscoveryProviderCertificateDataDto();
		dto.setUuid(uuid);
		dto.setBase64Content(base64Content);
		dto.setMeta(AttributeDefinitionUtils.deserialize(meta, MetadataAttribute.class));
		return dto;
	}

	@Override
    public String toString() {
        return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                .append("id", id)
				.append("uuid", uuid)
                .toString();
    }

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getBase64Content() {
		return base64Content;
	}

	public void setBase64Content(String base64Content) {
		this.base64Content = base64Content;
	}

	public Long getDiscoveryId() {
		return discoveryId;
	}

	public void setDiscoveryId(Long discoveryId) {
		this.discoveryId = discoveryId;
	}

	public String getMeta() {
		return meta;
	}

	public void setMeta(String meta) {
		this.meta = meta;
	}
}
