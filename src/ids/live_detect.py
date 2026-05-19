from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib

from .web import (
    DEFAULT_DB_PATH,
    DEFAULT_MODEL_PATH,
    get_expected_columns,
    predict_records,
    save_prediction_logs,
)


LOGIN_PORTS = {21, 22, 23, 3389}


@dataclass
class FlowState:
    src: str
    dst: str
    protocol: str
    first_seen: float
    last_seen: float
    src_bytes: int = 0
    dst_bytes: int = 0
    packets: int = 0
    errors: int = 0
    login_attempts: int = 0
    last_prediction_at: float = 0

    def as_features(self) -> dict[str, Any]:
        return {
            "duration": round(max(self.last_seen - self.first_seen, 0.001), 6),
            "protocol": self.protocol,
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "packets": self.packets,
            "errors": self.errors,
            "login_attempts": self.login_attempts,
        }


class PacketFeatureExtractor:
    def __init__(self) -> None:
        self.flows: dict[tuple[str, str, str], FlowState] = {}

    def observe(
        self,
        src: str,
        dst: str,
        protocol: str,
        size: int,
        timestamp: float | None = None,
        is_error: bool = False,
        is_login_attempt: bool = False,
    ) -> FlowState:
        now = timestamp if timestamp is not None else time.time()
        forward_key = (src, dst, protocol)
        reverse_key = (dst, src, protocol)

        if forward_key in self.flows:
            flow = self.flows[forward_key]
            flow.src_bytes += size
        elif reverse_key in self.flows:
            flow = self.flows[reverse_key]
            flow.dst_bytes += size
        else:
            flow = FlowState(
                src=src,
                dst=dst,
                protocol=protocol,
                first_seen=now,
                last_seen=now,
                src_bytes=size,
            )
            self.flows[forward_key] = flow

        flow.last_seen = now
        flow.packets += 1
        if is_error:
            flow.errors += 1
        if is_login_attempt:
            flow.login_attempts += 1
        return flow


def packet_to_observation(packet) -> dict[str, Any] | None:
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if IP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = "other"
    is_error = False
    is_login_attempt = False

    if TCP in packet:
        tcp_layer = packet[TCP]
        protocol = "tcp"
        is_error = "R" in str(tcp_layer.flags)
        is_login_attempt = tcp_layer.dport in LOGIN_PORTS
    elif UDP in packet:
        udp_layer = packet[UDP]
        protocol = "udp"
        is_login_attempt = udp_layer.dport in LOGIN_PORTS
    elif ICMP in packet:
        icmp_layer = packet[ICMP]
        protocol = "icmp"
        is_error = icmp_layer.type in {3, 11, 12}

    return {
        "src": ip_layer.src,
        "dst": ip_layer.dst,
        "protocol": protocol,
        "size": len(packet),
        "timestamp": float(getattr(packet, "time", time.time())),
        "is_error": is_error,
        "is_login_attempt": is_login_attempt,
    }


def should_predict(flow: FlowState, min_packets: int, cooldown: float, now: float) -> bool:
    return flow.packets >= min_packets and now - flow.last_prediction_at >= cooldown


def record_for_model(model, flow_features: dict[str, Any]) -> dict[str, Any]:
    expected_columns = get_expected_columns(model)
    if "protocol_type" not in expected_columns:
        return flow_features

    record = build_nsl_kdd_live_record(flow_features)
    return {column: record[column] for column in expected_columns if column in record}


def build_nsl_kdd_live_record(flow_features: dict[str, Any]) -> dict[str, Any]:
    protocol = flow_features.get("protocol", "tcp")
    packets = int(flow_features.get("packets", 0))
    errors = int(flow_features.get("errors", 0))
    src_bytes = float(flow_features.get("src_bytes", 0))
    dst_bytes = float(flow_features.get("dst_bytes", 0))
    error_rate = min(errors / packets, 1.0) if packets else 0.0

    return {
        "duration": flow_features.get("duration", 0),
        "protocol_type": protocol,
        "service": "private",
        "flag": "S0" if errors else "SF",
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": flow_features.get("login_attempts", 0),
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": packets,
        "srv_count": packets,
        "serror_rate": error_rate,
        "srv_serror_rate": error_rate,
        "rerror_rate": error_rate,
        "srv_rerror_rate": error_rate,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": min(packets, 255),
        "dst_host_srv_count": min(packets, 255),
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": error_rate,
        "dst_host_srv_serror_rate": error_rate,
        "dst_host_rerror_rate": error_rate,
        "dst_host_srv_rerror_rate": error_rate,
    }


def run_live_detection(
    model_path: Path,
    database_path: Path,
    interface: str | None = None,
    packet_filter: str | None = None,
    min_packets: int = 5,
    cooldown: float = 5.0,
) -> None:
    from scapy.all import sniff

    model = joblib.load(model_path)
    extractor = PacketFeatureExtractor()

    print(f"Loaded IDS model: {model_path}")
    print(f"Writing live alerts to: {database_path}")
    print("Starting live packet capture. Press Ctrl+C to stop.")

    def handle_packet(packet) -> None:
        observation = packet_to_observation(packet)
        if observation is None:
            return

        flow = extractor.observe(**observation)
        now = observation["timestamp"]
        if not should_predict(flow, min_packets=min_packets, cooldown=cooldown, now=now):
            return

        record = record_for_model(model, flow.as_features())
        response = predict_records(model, [record], model_path)
        save_prediction_logs(
            database_path,
            [record],
            response["predictions"],
            response["model_path"],
        )
        flow.last_prediction_at = now
        prediction = response["predictions"][0]
        probability = prediction.get("attack_probability", 0)
        print(
            f"{flow.src} -> {flow.dst} {flow.protocol} "
            f"prediction={prediction['prediction']} "
            f"probability={probability:.3f} "
            f"threat={prediction['threat_level']}"
        )

    sniff(
        iface=interface,
        filter=packet_filter,
        prn=handle_packet,
        store=False,
    )


def list_interfaces() -> None:
    from scapy.all import get_if_list

    for interface in get_if_list():
        print(interface)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture live packets with Scapy and run real-time IDS predictions."
    )
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--database", default=str(DEFAULT_DB_PATH))
    parser.add_argument("--interface", help="Network interface name to sniff.")
    parser.add_argument("--filter", default="ip", help="Optional BPF filter for Scapy.")
    parser.add_argument("--min-packets", type=int, default=5)
    parser.add_argument("--cooldown", type=float, default=5.0)
    parser.add_argument("--list-interfaces", action="store_true")
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    run_live_detection(
        model_path=Path(args.model),
        database_path=Path(args.database),
        interface=args.interface,
        packet_filter=args.filter,
        min_packets=args.min_packets,
        cooldown=args.cooldown,
    )


if __name__ == "__main__":
    main()
