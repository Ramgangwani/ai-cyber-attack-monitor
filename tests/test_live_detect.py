from src.ids.live_detect import (
    PacketFeatureExtractor,
    build_nsl_kdd_live_record,
    should_predict,
)


def test_packet_feature_extractor_aggregates_bidirectional_flow():
    extractor = PacketFeatureExtractor()

    extractor.observe("10.0.0.1", "10.0.0.2", "tcp", 100, timestamp=1.0)
    flow = extractor.observe("10.0.0.2", "10.0.0.1", "tcp", 60, timestamp=3.0)

    features = flow.as_features()

    assert features["duration"] == 2.0
    assert features["protocol"] == "tcp"
    assert features["src_bytes"] == 100
    assert features["dst_bytes"] == 60
    assert features["packets"] == 2


def test_packet_feature_extractor_counts_error_and_login_attempts():
    extractor = PacketFeatureExtractor()

    flow = extractor.observe(
        "10.0.0.1",
        "10.0.0.2",
        "tcp",
        100,
        timestamp=1.0,
        is_error=True,
        is_login_attempt=True,
    )

    features = flow.as_features()

    assert features["errors"] == 1
    assert features["login_attempts"] == 1


def test_should_predict_respects_min_packets_and_cooldown():
    extractor = PacketFeatureExtractor()
    flow = extractor.observe("10.0.0.1", "10.0.0.2", "tcp", 100, timestamp=1.0)
    flow.last_prediction_at = 8.0

    assert should_predict(flow, min_packets=2, cooldown=5.0, now=10.0) is False

    extractor.observe("10.0.0.1", "10.0.0.2", "tcp", 100, timestamp=2.0)

    assert should_predict(flow, min_packets=2, cooldown=5.0, now=10.0) is False
    assert should_predict(flow, min_packets=2, cooldown=1.0, now=10.0) is True


def test_build_nsl_kdd_live_record_maps_flow_features():
    record = build_nsl_kdd_live_record(
        {
            "duration": 2.5,
            "protocol": "tcp",
            "src_bytes": 500,
            "dst_bytes": 100,
            "packets": 10,
            "errors": 2,
            "login_attempts": 1,
        }
    )

    assert record["protocol_type"] == "tcp"
    assert record["src_bytes"] == 500
    assert record["dst_bytes"] == 100
    assert record["count"] == 10
    assert record["num_failed_logins"] == 1
    assert record["serror_rate"] == 0.2
