package com.otilm.discovery.ip.service.v2;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.connector.discovery.v2.DiscoveredItemDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDeliveryMode;
import com.otilm.api.model.connector.discovery.v2.DiscoveryDrainRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryInitiateRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryResultsResponseDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunRequestDto;
import com.otilm.api.model.connector.discovery.v2.DiscoveryRunState;
import com.otilm.api.model.connector.discovery.v2.DiscoveryV2ScopedRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.discovery.ip.dto.ConnectionResponse;
import com.otilm.discovery.ip.service.ConnectionService;
import com.otilm.discovery.ip.service.v2.impl.DiscoveryAttributeServiceImpl;
import com.otilm.discovery.ip.util.TargetEnumeration;
import java.math.BigInteger;
import java.net.ConnectException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.stream.LongStream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.info.BuildProperties;

/**
 * Two replicas that share nothing but the network they scan serve one run between them. A stand-in for Core stores what
 * each answer hands back and sends the next call to the other replica.
 */
class StatelessServingTest {

    private static final String HOSTS = "10.0.0.1-10.0.0.100";
    private static final String PORTS = "443,444,445,446,447";
    private static final TargetEnumeration TARGETS = TargetEnumeration.of(HOSTS, PORTS, false);
    private static final int PAGE_ITEMS = 100;
    private static final long PAGE_BYTES = 1L << 20;

    private static X509Certificate leaf;
    private static X509Certificate issuer;
    private static Map<String, Long> indexByUrl;

    /** Two certificates on every fifth target, nothing listening on the rest. */
    private final ConnectionService network = url -> {
        if (indexByUrl.get(url) % 5 != 0) {
            throw new ConnectException("Connection refused");
        }
        return new ConnectionResponse("TLS_AES_256_GCM_SHA384", new X509Certificate[]{leaf, issuer});
    };

    private final CheckpointedRunService first = replica();
    private final CheckpointedRunService second = replica();

    @BeforeAll
    static void prepare() throws Exception {
        leaf = mint("CN=stateless-leaf");
        issuer = mint("CN=stateless-issuer");
        indexByUrl = new HashMap<>();
        for (long index = 0; index < TARGETS.size(); index++) {
            indexByUrl.put(TARGETS.target(index), index);
        }
    }

    private static X509Certificate mint(String name) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        KeyPair pair = generator.generateKeyPair();
        X500Principal subject = new X500Principal(name);
        return new JcaX509CertificateConverter()
                .getCertificate(new JcaX509v3CertificateBuilder(subject, BigInteger.ONE,
                        Date.from(Instant.now().minus(Duration.ofDays(1))),
                        Date.from(Instant.now().plus(Duration.ofDays(1))), subject, pair.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(pair.getPrivate())));
    }

    /** Everything a replica holds is built here, so the two have no object in common besides the network. */
    private CheckpointedRunService replica() {
        SliceSettings settings = new SliceSettings(8_000, 32, 256, 10_000);
        AbandonedProbes abandoned = new AbandonedProbes();
        Properties properties = new Properties();
        properties.setProperty("version", "1.8.0-SNAPSHOT");
        return new CheckpointedRunService(
                new SliceScanner(new TargetProber(network, abandoned), settings, new ProbePermits(2_000)), settings,
                abandoned, new DiscoveryAttributeServiceImpl(new BuildProperties(properties)));
    }

    private static <T extends DiscoveryV2ScopedRequestDto> T scoped(T request, UUID runId,
            List<MetadataAttribute> checkpoint) {
        request.setRunId(runId);
        request.setResources(List.of(Resource.CERTIFICATE));
        request
                .setAttributes(List
                        .of(text(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_UUID,
                                DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_HOSTS_NAME, HOSTS),
                                text(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_UUID,
                                        DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PORTS_NAME, PORTS),
                                parallelism(8)));
        request.setDeliveryModes(List.of(DiscoveryDeliveryMode.CHECKPOINTED));
        request.setCheckpoint(checkpoint);
        return request;
    }

    private static RequestAttribute text(String uuid, String name, String... values) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(uuid));
        attribute.setName(name);
        attribute.setContentType(AttributeContentType.STRING);
        attribute
                .setContent(java.util.Arrays
                        .stream(values)
                        .<BaseAttributeContentV3<?>>map(StringAttributeContentV3::new)
                        .toList());
        return attribute;
    }

    private static RequestAttribute parallelism(int value) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_UUID));
        attribute.setName(DiscoveryAttributeServiceImpl.DATA_ATTRIBUTE_PARALLEL_EXECUTIONS_NAME);
        attribute.setContentType(AttributeContentType.INTEGER);
        attribute.setContent(List.of(new IntegerAttributeContentV3(value)));
        return attribute;
    }

    private static DiscoveryDrainRequestDto drain(UUID runId, List<MetadataAttribute> checkpoint, long afterSequence) {
        DiscoveryDrainRequestDto request = scoped(new DiscoveryDrainRequestDto(), runId, checkpoint);
        request.setAfterSequence(afterSequence);
        request.setMaxItems(PAGE_ITEMS);
        request.setMaxBytes(PAGE_BYTES);
        return request;
    }

    /** Where an item came from and what it is; its sequence is asserted separately. */
    private static String identity(DiscoveredItemDto item) {
        MetadataAttributeV3 source = (MetadataAttributeV3) item.getMeta().getFirst();
        return source.getContent().getFirst().getData() + " " + item.getUniqueRef();
    }

    private static Object textOf(List<MetadataAttribute> checkpoint) {
        return ((MetadataAttributeV3) checkpoint.getFirst()).getContent().getFirst().getData();
    }

    @Test
    void alternatingReplicasDeliverEveryItemOnceInOneDenseSequence() {
        UUID runId = UUID.randomUUID();
        List<MetadataAttribute> checkpoint = first
                .initiate(scoped(new DiscoveryInitiateRequestDto(), runId, null))
                .getCheckpoint();
        long afterSequence = 0;
        List<DiscoveredItemDto> delivered = new ArrayList<>();
        DiscoveryResultsResponseDto page;
        int calls = 0;
        do {
            CheckpointedRunService replica = calls++ % 2 == 0 ? second : first;
            page = replica.results(drain(runId, checkpoint, afterSequence));
            delivered.addAll(page.getItems());
            afterSequence = page.getHighestSequence();
            checkpoint = page.getCheckpoint();
        } while (page.getMore() && calls < 50);

        Assertions.assertFalse(page.getMore(), "the run ends with more: false");
        Assertions.assertTrue(calls > 2, "the run was served in several slices, by both replicas");
        Assertions
                .assertEquals(LongStream.rangeClosed(1, 200).boxed().toList(),
                        delivered.stream().map(DiscoveredItemDto::getSequence).toList(),
                        "sequences run 1..200 with no gap and no repeat");
        Set<String> distinct = new HashSet<>(delivered.stream().map(StatelessServingTest::identity).toList());
        Assertions.assertEquals(200, distinct.size(), "every item is delivered once");

        DiscoveryRunRequestDto status = scoped(new DiscoveryRunRequestDto(), runId, checkpoint);
        Assertions.assertEquals(DiscoveryRunState.COMPLETED, first.status(status).getState());
        Assertions.assertEquals(200L, second.status(status).getHighestSequence());
    }

    /**
     * Core may deliver one drain twice at once. When neither answer is cut short by its scan budget, as here, where
     * every probe answers at once and the page limit ends the slice, both are the same page and the same checkpoint.
     * Under uneven load one replica's budget can run out first; its answer is then a prefix of the other's, and Core
     * applies whichever it receives first by checkpoint revision.
     */
    @Test
    void oneRequestServedByBothReplicasAtOnceGivesTheSameAnswer() throws Exception {
        UUID runId = UUID.randomUUID();
        List<MetadataAttribute> initial = first
                .initiate(scoped(new DiscoveryInitiateRequestDto(), runId, null))
                .getCheckpoint();
        DiscoveryDrainRequestDto request = drain(runId, initial, 0);
        CountDownLatch start = new CountDownLatch(1);

        CompletableFuture<DiscoveryResultsResponseDto> fromFirst = CompletableFuture.supplyAsync(() -> {
            awaitQuietly(start);
            return first.results(request);
        });
        CompletableFuture<DiscoveryResultsResponseDto> fromSecond = CompletableFuture.supplyAsync(() -> {
            awaitQuietly(start);
            return second.results(request);
        });
        start.countDown();
        DiscoveryResultsResponseDto a = fromFirst.get(30, TimeUnit.SECONDS);
        DiscoveryResultsResponseDto b = fromSecond.get(30, TimeUnit.SECONDS);

        Assertions.assertEquals(PAGE_ITEMS, a.getItems().size());
        Assertions
                .assertEquals(a.getItems().stream().map(item -> item.getSequence() + " " + identity(item)).toList(),
                        b.getItems().stream().map(item -> item.getSequence() + " " + identity(item)).toList());
        Assertions.assertEquals(textOf(a.getCheckpoint()), textOf(b.getCheckpoint()));
        Assertions.assertEquals(a.getHighestSequence(), b.getHighestSequence());
        Assertions.assertEquals(a.getMore(), b.getMore());
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
