# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

import argparse
from enum import Enum
import glob
import json
import math
import os
import matplotlib.pyplot as plt
import matplotlib.ticker as tick
from glob import glob
from itertools import cycle

# A simple python script to plot measurements results. This script requires
# the following dependencies: `pip install matplotlib`.

# Constants for data filtering
WARM_UP_THRESHOLD = 240
COOL_DOWN_THRESHOLD = 3

def get_valid_data_window(data_points):
    """
    Returns the start and end data points defining the valid measurement window.
    Excludes warm-up (first 40s) and cool-down (last 3s).
    """
    if not data_points:
        return None, None

    # 1. Find max duration to determine cutoff for cool-down
    total_duration = float(data_points[-1]['timestamp']['secs'])
    cutoff_time = total_duration - COOL_DOWN_THRESHOLD

    # 2. Find Start (Warm-up)
    start_point = None
    start_idx = -1
    for i, p in enumerate(data_points):
        if float(p['timestamp']['secs']) > WARM_UP_THRESHOLD:
            start_point = p
            start_idx = i
            break

    if start_point is None:
        return None, None

    # 3. Find End (Cool-down)
    end_point = None
    # Search backwards from the end to find the last point within cutoff
    for i in range(len(data_points) - 1, start_idx, -1):
        p = data_points[i]
        if float(p['timestamp']['secs']) <= cutoff_time:
            end_point = p
            break

    if end_point is None:
        return None, None

    # Check if window is valid (start comes before end)
    if float(start_point['timestamp']['secs']) >= float(end_point['timestamp']['secs']):
        return None, None

    return start_point, end_point

def aggregate_tps(measurement, workload):
    if workload not in measurement['data']:
        return 0

    tps_values = []
    for data in measurement['data'][workload].values():
        start, end = get_valid_data_window(data)
        if start and end:
            duration = float(end['timestamp']['secs']) - float(start['timestamp']['secs'])
            count = float(end['count']) - float(start['count'])
            if duration > 0:
                tps_values.append(count / duration)
            else:
                tps_values.append(0)
        else:
            tps_values.append(0)

    return max(tps_values) if tps_values else 0


def aggregate_average_latency(measurement, workload):
    if workload not in measurement['data']:
        return 0

    latencies = []
    for data in measurement['data'][workload].values():
        start, end = get_valid_data_window(data)
        if start and end:
            count = float(end['count']) - float(start['count'])
            total = float(end['sum']['secs']) - float(start['sum']['secs'])
            if count > 0:
                latencies.append(total / count)
            else:
                latencies.append(0)

    return sum(latencies) / len(latencies) if latencies else 0


def aggregate_stdev_latency(measurement, workload):
    if workload not in measurement['data']:
        return 0

    stdevs = []
    for data in measurement['data'][workload].values():
        start, end = get_valid_data_window(data)
        if start and end:
            count = float(end['count']) - float(start['count'])
            if count > 0:
                latency_sum = float(end['sum']['secs']) - float(start['sum']['secs'])
                latency_square_sum = float(end['squared_sum']) - float(start['squared_sum'])
                first_term = latency_square_sum / count
                second_term = (latency_sum / count)**2

                variance = first_term - second_term
                if variance > 0:
                    stdevs.append(math.sqrt(variance))
                else:
                    stdevs.append(0)
            else:
                stdevs.append(0)

    return max(stdevs) if stdevs else 0

def get_fault_delay(measurement):
    """
    settings에서 장애 주입 시점(초)을 추출합니다.
    """
    try:
        faults = measurement['parameters']['settings']['faults']
        # Rust Enum 직렬화 방식에 따라 'Static' 키가 있을 수 있음
        if 'Static' in faults:
            conf = faults['Static']
            # Crash가 설정되어 있으면 crash_delay 반환
            if conf.get('crash_nodes', 0) > 0:
                d = conf.get('crash_delay', {})
                return float(d.get('secs', 0)) + float(d.get('nanos', 0)) / 1e9
            # Byzantine이 설정되어 있으면 byzantine_delay 반환
            if conf.get('byzantine_nodes', 0) > 0:
                d = conf.get('byzantine_delay', {})
                return float(d.get('secs', 0)) + float(d.get('nanos', 0)) / 1e9
    except Exception as e:
        print(f"Failed to extract fault delay: {e}")
    return None

def aggregate_p_latency(measurement, workload, p=50):
    if workload not in measurement['data']:
        return 0

    latencies = []
    for data in measurement['data'][workload].values():
        start, end = get_valid_data_window(data)
        if not (start and end):
            continue

        # Calculate count in the window
        count = float(end['count']) - float(start['count'])
        if count <= 0:
            continue

        # Reconstruct buckets for the window
        buckets_start = start['buckets']
        buckets_end = end['buckets']

        window_buckets = []
        # Iterate over all keys in end buckets
        for le, c_end in buckets_end.items():
            c_start = buckets_start.get(le, 0)
            window_buckets.append((float(le), c_end - c_start))

        window_buckets.sort(key=lambda x: x[0])

        for l, c in window_buckets:
            if c >= count * p / 100:
                latencies.append(l)
                break

    return sum(latencies) / len(latencies) if latencies else 0

# [Modified] Function to calculate average CPU usage over a steady state period
def aggregate_cpu_usage(measurement, cores=32):
    if 'system' not in measurement['data']:
        return 0, 0

    node_cpu_avgs = []

    for scraper_id, data_points in measurement['data']['system'].items():
        data_points.sort(key=lambda x: float(x['timestamp']['secs']))

        # Use standardized window function
        start, end = get_valid_data_window(data_points)

        if not (start and end):
            continue

        # Calculate usage based on accumulated CPU seconds and elapsed time
        delta_cpu = float(end['cpu_accumulated_seconds']) - float(start['cpu_accumulated_seconds'])
        delta_time = float(end['timestamp']['secs']) - float(start['timestamp']['secs'])

        if delta_time > 0:
            # Normalize by number of cores to get percentage (0-100%)
            avg_usage = (delta_cpu / delta_time / cores) * 100
            node_cpu_avgs.append(avg_usage)

    if not node_cpu_avgs:
        return 0, 0

    # Calculate global average across all nodes
    global_avg = sum(node_cpu_avgs) / len(node_cpu_avgs)

    # Calculate standard deviation
    variance = sum((x - global_avg) ** 2 for x in node_cpu_avgs) / len(node_cpu_avgs)
    stdev = math.sqrt(variance)

    return global_avg, stdev

def aggregate_breakdown_components(measurement, workload):
    """
    Returns a dict of average latencies for each component.
    """
    # 1. Workload 찾기
    target_workload = workload
    if workload not in measurement['data']:
        keys = list(measurement['data'].keys())
        if keys:
            target_workload = keys[0]
        else:
            return {}

    data_source = measurement['data'][target_workload]
    iterator = data_source.values() if isinstance(data_source, dict) else data_source

    sums = {
        'queue': 0.0, 'verify': 0.0, 'pre_con': 0.0, 'cert': 0.0,
        'commit_fpc': 0.0, 'commit_c': 0.0, 'count': 0.0
    }

    # [변경] 안정화 구간 240초로 설정
    ramp_up_threshold = 240

    for data in iterator:
        start_snapshot = None
        for point in data:
            if float(point['timestamp']['secs']) > ramp_up_threshold:
                start_snapshot = point
                break

        if not start_snapshot:
            continue

        end_snapshot = data[-1]

        count = float(end_snapshot['count']) - float(start_snapshot['count'])
        if count <= 0: continue

        sums['count'] += count

        key_map = {
            'queue': 'breakdown_queue_sum',
            'verify': 'breakdown_verify_sum',
            'pre_con': 'breakdown_pre_consensus_sum',
            'cert': 'breakdown_cert_sum',
            'commit_fpc': 'breakdown_commit_fpc_sum',
            'commit_c': 'breakdown_commit_c_sum'
        }

        for dict_key, json_key in key_map.items():
            val_end = float(end_snapshot.get(json_key, 0))
            val_start = float(start_snapshot.get(json_key, 0))
            sums[dict_key] += (val_end - val_start)

    if sums['count'] == 0:
        return {}

    avgs = {k: v / sums['count'] for k, v in sums.items() if k != 'count'}

    return avgs

def aggregate_network_bandwidth(measurement):
    if 'system' not in measurement['data']:
        return 0, 0

    in_rates = []
    out_rates = []

    # 각 노드(scraper_id)별로 데이터를 순회
    for scraper_id, data_points in measurement['data']['system'].items():
        data_points.sort(key=lambda x: float(x['timestamp']['secs']))

        # Use standardized window function
        start, end = get_valid_data_window(data_points)

        if not (start and end):
            continue

        delta_time = float(end['timestamp']['secs']) - float(start['timestamp']['secs'])

        if delta_time > 0:
            # 수신 대역폭 계산 (Bytes -> MB 변환)
            delta_in = float(end.get('system_network_in_bytes', 0)) - float(start.get('system_network_in_bytes', 0))
            in_rate_mbps = (delta_in / delta_time) / (1024 * 1024)
            in_rates.append(in_rate_mbps)

            # 송신 대역폭 계산 (Bytes -> MB 변환)
            delta_out = float(end.get('system_network_out_bytes', 0)) - float(start.get('system_network_out_bytes', 0))
            out_rate_mbps = (delta_out / delta_time) / (1024 * 1024)
            out_rates.append(out_rate_mbps)

    if not in_rates:
        return 0, 0

    # 전체 노드의 평균 대역폭 계산
    avg_in_mbps = sum(in_rates) / len(in_rates)
    avg_out_mbps = sum(out_rates) / len(out_rates)

    return avg_in_mbps, avg_out_mbps


class PlotType(Enum):
    L_GRAPH = 1
    HEALTH = 2
    SCALABILITY = 3
    INSPECT_TPS = 4
    INSPECT_LATENCY = 5
    DURATION_TPS = 6
    DURATION_LATENCY = 7


class PlotError(Exception):
    pass


@tick.FuncFormatter
def default_major_formatter(x, pos):
    if pos is None:
        return
    return f'{x/1000:.0f}k' if x >= 10_000 else f'{x:,.0f}'


@tick.FuncFormatter
def sec_major_formatter(x, pos):
    if pos is None:
        return
    return f'{x:,.0f}' if x >= 10 else f'{x:,.1f}'


class PlotParameters:
    def __init__(self, transaction_size, nodes, faults, specs=None, commit=None):
        self.nodes = nodes
        self.faults = faults
        self.transaction_size = transaction_size
        self.specs = specs
        self.commit = commit


class MeasurementId:
    def __init__(self, measurement, workload, max_latency=None):
        # [수정 1] transaction_size 경로 변경 (benchmark_type -> client_parameters)
        if 'client_parameters' in measurement['parameters']:
            self.transaction_size = measurement['parameters']['client_parameters']['transaction_size']
        else:
            # 구버전 호환성 유지
            self.transaction_size = measurement['parameters']['benchmark_type']['transaction_size']

        self.nodes = measurement['parameters']['nodes']

        # [수정 2] faults 경로 및 구조 변경
        # JSON 구조: parameters -> settings -> faults -> Permanent -> faults
        self.faults = 0
        try:
            if 'settings' in measurement['parameters'] and 'faults' in measurement['parameters']['settings']:
                faults_conf = measurement['parameters']['settings']['faults']
                if 'Permanent' in faults_conf:
                    self.faults = faults_conf['Permanent'].get('faults', 0)
            elif 'faults' in measurement['parameters']:
                if 'Permanent' in measurement['parameters']['faults']:
                    self.faults = measurement['parameters']['faults']['Permanent']['faults']
        except (KeyError, TypeError):
            self.faults = 0

        # [수정 3] duration 경로 변경
        if 'settings' in measurement['parameters'] and 'benchmark_duration' in measurement['parameters']['settings']:
            self.duration = measurement['parameters']['settings']['benchmark_duration']
        elif 'duration' in measurement['parameters']:
            self.duration = measurement['parameters']['duration']
        else:
            self.duration = 0

        # [수정 4] machine_specs 경로 변경
        if 'settings' in measurement['parameters'] and 'specs' in measurement['parameters']['settings']:
            self.machine_specs = measurement['parameters']['settings']['specs']
        elif 'machine_specs' in measurement:
            self.machine_specs = measurement['machine_specs']
        else:
            self.machine_specs = "unknown"

        # [수정 5] commit 정보 경로 변경
        if 'settings' in measurement['parameters'] and 'repository' in measurement['parameters']['settings']:
            self.commit = measurement['parameters']['settings']['repository'].get('commit', 'unknown')
        elif 'commit' in measurement:
            self.commit = measurement['commit']
        else:
            self.commit = "unknown"

        self.workload = workload
        self.max_latency = max_latency


class Plotter:
    def __init__(self, data_directory, parameters, y_max=None, legend_columns=2, median=True):
        self.data_directory = data_directory
        self.parameters = parameters
        self.y_max = y_max
        self.legend_columns = legend_columns
        self.median = median

    def _make_plot_directory(self):
        plot_directory = os.path.join(self.data_directory, 'plots')
        if not os.path.exists(plot_directory):
            os.makedirs(plot_directory)

        return plot_directory

    def _legend_entry(self, plot_type, id):
        if plot_type in [PlotType.L_GRAPH, PlotType.HEALTH]:
            f = '' if id.faults == 0 else f' ({id.faults} faulty)'
            l = f'{id.nodes} nodes{f}'
            return f'{l} - {id.workload} ({id.transaction_size}B tx)'
        elif plot_type == PlotType.SCALABILITY:
            f = '' if id.faults == 0 else f' ({id.faults} faulty)'
            l = f'{id.max_latency}s latency cap{f}'
            return f'{l} - {id.workload} ({id.transaction_size}B tx)'
        else:
            return None

    def _axes_labels(self, plot_type):
        if plot_type == PlotType.L_GRAPH:
            return ('Throughput (tx/s)', 'Latency (s)')
        elif plot_type == PlotType.HEALTH:
            return ('Input Load (tx/s)', 'Throughput (tx/s)')
        elif plot_type == PlotType.SCALABILITY:
            return ('Committee size', 'Throughput (tx/s)')
        elif plot_type in [PlotType.INSPECT_TPS, PlotType.DURATION_TPS]:
            return ('Duration (s)', 'Throughput (tx/s)')
        elif plot_type in [PlotType.INSPECT_LATENCY, PlotType.DURATION_LATENCY]:
            return ('Duration (s)', 'Latency (s)')
        else:
            assert False

    def _plot(self, data, plot_type):
        plt.figure(figsize=(6.4, 2.4))
        markers = cycle(['o', 'v', 's', 'p', 'D', 'P'])

        for id, x_values, y_values, e_values in data:
            plt.errorbar(
                x_values, y_values, yerr=e_values,
                label=self._legend_entry(plot_type, id),
                linestyle='dotted', marker=next(markers), capsize=3
            )

        if plot_type == PlotType.L_GRAPH:
            legend_anchor, legend_location = (0.5, 1), 'lower center'
            plot_name = f'latency-{self.parameters.transaction_size}'
        elif plot_type == PlotType.HEALTH:
            legend_anchor, legend_location = (0, 1), 'upper left'
            plot_name = f'health-{self.parameters.transaction_size}'
        elif plot_type == PlotType.SCALABILITY:
            legend_anchor, legend_location = (0, 0), 'lower left'
            plot_name = f'scalability-{self.parameters.transaction_size}'
        elif plot_type == PlotType.INSPECT_TPS:
            plot_name = f'inspect-tps-{id}'
        elif plot_type == PlotType.INSPECT_LATENCY:
            plot_name = f'inspect-latency-{id}'
        elif plot_type == PlotType.DURATION_TPS:
            plot_name = f'inspect-aggregate-tps-{id}'
        elif plot_type == PlotType.DURATION_LATENCY:
            plot_name = f'inspect-aggregate-latency-{id}'
        else:
            assert False

        x_label, y_label = self._axes_labels(plot_type)

        skip_legend = plot_type in [
            PlotType.INSPECT_TPS,
            PlotType.INSPECT_LATENCY,
            PlotType.DURATION_TPS,
            PlotType.DURATION_LATENCY,
        ]
        if data and (not skip_legend):
            plt.legend(
                loc=legend_location,
                bbox_to_anchor=legend_anchor,
                ncol=self.legend_columns
            )
        plt.xlim(xmin=0)
        plt.ylim(bottom=0)
        if plot_type == PlotType.L_GRAPH:
            plt.ylim(top=self.y_max)
        plt.xlabel(x_label, fontweight='bold')
        plt.ylabel(y_label, fontweight='bold')
        plt.xticks(weight='bold')
        plt.yticks(weight='bold')
        plt.grid()
        ax = plt.gca()
        ax.xaxis.set_major_formatter(default_major_formatter)
        ax.yaxis.set_major_formatter(default_major_formatter)
        if plot_type in [PlotType.L_GRAPH, PlotType.INSPECT_LATENCY]:
            ax.yaxis.set_major_formatter(sec_major_formatter)

        for x in ['pdf', 'png']:
            filename = os.path.join(
                self._make_plot_directory(), f'{plot_name}.{x}'
            )
            plt.savefig(filename, bbox_inches='tight')

    def _load_measurement_data(self, filename):
        measurements = []
        files = glob(os.path.join(self.data_directory, filename))
        for file in files:
            with open(file, 'r') as f:
                try:
                    measurements += [json.loads(f.read())]
                except json.JSONDecodeError as e:
                    raise PlotError(f'Failed to load file {file}: {e}')

        return measurements

    def _file_format(self, transaction_size, faults, nodes, load):
        return f'measurements-fpc-{transaction_size}-{faults}-{nodes}-{load}.json'

    def plot_latency_throughput(self, workload):
        plot_lines_data = []
        transaction_size = self.parameters.transaction_size
        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                plot_lines_data += [self._load_measurement_data(filename)]

        plot_data = []
        for measurements in plot_lines_data:
            for w in workload:
                x_values, y_values, e_values = [], [], []
                measurements.sort(key=lambda x: x['parameters']['load'])
                for measurement in measurements:
                    x_values += [aggregate_tps(measurement, w)]
                    if self.median:
                        y_values += [aggregate_p_latency(measurement, w, p=50)]
                        e_values += [aggregate_p_latency(measurement, w, p=75)]
                    else:
                        y_values += [aggregate_average_latency(measurement, w)]
                        e_values += [aggregate_stdev_latency(measurement, w)]

                if x_values:
                    id = MeasurementId(measurements[0], w)
                    plot_data += [(id, x_values, y_values, e_values)]

        self._plot(plot_data, PlotType.L_GRAPH)

    def plot_fault_time_series(self, workload):
        transaction_size = self.parameters.transaction_size

        # 색상 정의
        colors = {
            'queue': '#d3d3d3',      # 회색
            'verify': '#ff7f0e',     # 주황
            'batching': '#1f77b4',   # 파랑
            'cert': '#2ca02c',       # 초록
            'commit': '#d62728',     # 빨강
        }

        labels = {
            'queue': 'Queue',
            'verify': 'Verify',
            'batching': 'Batching',
            'cert': 'Certification',
            'commit': 'Commitment'
        }

        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                measurements_list = self._load_measurement_data(filename)
                if not measurements_list: continue

                measurement = max(measurements_list, key=lambda x: x['parameters']['load'])
                fault_time = get_fault_delay(measurement)

                if workload[0] not in measurement['data']: continue

                precision = 1.0
                time_buckets = {}

                for node_id, points in measurement['data'][workload[0]].items():
                    points.sort(key=lambda x: float(x['timestamp']['secs']))

                    for i in range(1, len(points)):
                        prev = points[i-1]
                        curr = points[i]

                        t_prev = float(prev['timestamp']['secs'])
                        t_curr = float(curr['timestamp']['secs'])
                        dt = t_curr - t_prev

                        if dt <= 0: continue

                        t_mid = (t_prev + t_curr) / 2
                        bucket_key = int(t_mid / precision) * precision

                        d_count = float(curr['count']) - float(prev['count'])
                        if d_count <= 0: continue

                        tps = d_count / dt

                        # --- Latency Components Delta (평균) 계산 ---
                        def get_delta_avg(key):
                            val_curr = float(curr.get(key, 0))
                            val_prev = float(prev.get(key, 0))
                            return max(0, (val_curr - val_prev) / d_count)

                        # 1. Raw Metrics 추출
                        raw_queue = get_delta_avg('breakdown_queue_sum')
                        raw_verify = get_delta_avg('breakdown_verify_sum')
                        raw_pre_con = get_delta_avg('breakdown_pre_consensus_sum')
                        raw_cert = get_delta_avg('breakdown_cert_sum')

                        # Commit은 FPC와 C-Path 합산 (Raw 값: Block Creation ~ Commit)
                        val_commit_curr = float(curr.get('breakdown_commit_fpc_sum', 0)) + float(curr.get('breakdown_commit_c_sum', 0))
                        val_commit_prev = float(prev.get('breakdown_commit_fpc_sum', 0)) + float(prev.get('breakdown_commit_c_sum', 0))
                        raw_commit = max(0, (val_commit_curr - val_commit_prev) / d_count)

                        # 2. Layer별 순수 시간 계산 (Subtraction Logic)

                        # Layer 3: Batching = PreConsensus - (Queue + Verify)
                        layer_batching = max(0, raw_pre_con - (raw_queue + raw_verify))

                        # Layer 5: Pure Commit = Raw Commit - Raw Cert
                        # (Raw Commit은 Cert 시간을 포함하므로 빼줘야 함)
                        layer_commit = max(0, raw_commit - raw_cert)

                        if bucket_key not in time_buckets:
                            time_buckets[bucket_key] = {
                                'tps': 0,
                                'weight': 0,
                                'comps': {'queue': 0, 'verify': 0, 'batching': 0, 'cert': 0, 'commit': 0}
                            }

                        b = time_buckets[bucket_key]
                        b['tps'] += tps
                        b['weight'] += 1

                        # 계산된 Layer 값 누적
                        b['comps']['queue'] += raw_queue
                        b['comps']['verify'] += raw_verify
                        b['comps']['batching'] += layer_batching
                        b['comps']['cert'] += raw_cert
                        b['comps']['commit'] += layer_commit

                sorted_times = sorted(time_buckets.keys())
                if not sorted_times: continue

                x_time = []
                y_tps = []

                y_stacks = {
                    'queue': [], 'verify': [], 'batching': [], 'cert': [], 'commit': []
                }

                for t in sorted_times:
                    b = time_buckets[t]
                    w = b['weight'] if b['weight'] > 0 else 1

                    x_time.append(t)
                    y_tps.append(b['tps'])

                    # 노드 간 평균 계산
                    y_stacks['queue'].append(b['comps']['queue'] / w)
                    y_stacks['verify'].append(b['comps']['verify'] / w)
                    y_stacks['batching'].append(b['comps']['batching'] / w)
                    y_stacks['cert'].append(b['comps']['cert'] / w)
                    y_stacks['commit'].append(b['comps']['commit'] / w)

                # --- Plotting ---
                fig, (ax1, ax2) = plt.subplots(2, 1, sharex=True, figsize=(10, 8))

                # 상단: TPS
                ax1.plot(x_time, y_tps, label=f'Throughput (TPS)', color='black', linewidth=1.5)
                ax1.set_ylabel('Throughput (tx/s)', fontweight='bold')
                ax1.grid(True, linestyle='--', alpha=0.5)
                ax1.legend(loc='upper right')
                ax1.set_title(f'Fault Impact Analysis ({n} Nodes, {f} Faults)', fontweight='bold')

                # 하단: Latency Stacked Area
                stack_keys = ['queue', 'verify', 'batching', 'cert', 'commit']
                stack_data = [y_stacks[k] for k in stack_keys]
                stack_colors = [colors[k] for k in stack_keys]
                stack_labels = [labels[k] for k in stack_keys]

                ax2.stackplot(x_time, *stack_data, labels=stack_labels, colors=stack_colors, alpha=0.85)

                ax2.set_ylabel('Latency Breakdown (s)', fontweight='bold')
                ax2.set_xlabel('Time (s)', fontweight='bold')
                ax2.grid(True, linestyle='--', alpha=0.5)
                ax2.legend(loc='upper left', bbox_to_anchor=(1.0, 1.05), title="Latency Components")

                if fault_time is not None:
                    ax1.axvline(x=fault_time, color='red', linestyle='--', linewidth=2, label='Fault Injection')
                    ax2.axvline(x=fault_time, color='red', linestyle='--', linewidth=2)
                    ylim = ax1.get_ylim()
                    ax1.text(fault_time, ylim[1]*0.9, ' Fault', color='red', fontweight='bold')

                plt.tight_layout()

                plot_name = f'fault-breakdown-series-{n}-{transaction_size}.png'
                filename = os.path.join(self._make_plot_directory(), plot_name)
                plt.savefig(filename, bbox_inches='tight')
                print(f"Generated {filename}")

    def plot_health(self, workload):
        plot_lines_data = []
        transaction_size = self.parameters.transaction_size
        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                plot_lines_data += [self._load_measurement_data(filename)]

        plot_data = []
        for measurements in plot_lines_data:
            for w in workload:
                x_values, y_values, e_values = [], [], []
                measurements.sort(key=lambda x: x['parameters']['load'])
                for measurement in measurements:
                    x_values += [measurement['parameters']['load']]
                    y_values += [aggregate_tps(measurement, w)]
                    e_values += [0]

                if x_values:
                    id = MeasurementId(measurements[0], w)
                    plot_data += [(id, x_values, y_values, e_values)]

        self._plot(plot_data, PlotType.HEALTH)

    def plot_scalability(self, max_latencies, workload):
        plot_data = []

        for w in workload:
            plot_lines_data = []
            transaction_size = self.parameters.transaction_size
            for f in self.parameters.faults:
                for l in max_latencies:
                    filenames = []
                    for n in self.parameters.nodes:
                        filename = self._file_format(
                            transaction_size, f, n, '*'
                        )
                        measurements = self._load_measurement_data(filename)
                        measurements = [
                            x for x in measurements if aggregate_average_latency(x, w) <= l
                        ]
                        if measurements:
                            filenames += [
                                max(measurements, key=lambda x: aggregate_tps(x, w))
                            ]
                    plot_lines_data += [(filenames, l)]


            for measurements, max_latency in plot_lines_data:
                x_values, y_values, e_values = [], [], []
                for measurement in measurements:
                    x_values += [measurement['parameters']['nodes']]
                    y_values += [aggregate_tps(measurement, w)]
                    e_values += [0]

                if x_values:
                    id = MeasurementId(measurements[0], w, max_latency)
                    plot_data += [(id, x_values, y_values, e_values)]

        self._plot(plot_data, PlotType.SCALABILITY)

    def plot_inspect(self, file, workload):
        with open(file, 'r') as f:
            try:
                measurement = json.loads(f.read())
            except json.JSONDecodeError as e:
                raise PlotError(f'Failed to load file {file}: {e}')

        plot_tps_data, plot_lat_data = [], []
        for data in measurement['data'][workload].values():
            x_values, y_tps_values, y_lat_values, e_values = [], [], [], []
            for d in data:
                count = float(d['count'])
                duration = float(d['timestamp']['secs'])
                total = float(d['sum']['secs'])

                tps = (count / duration) if duration != 0 else 0
                avg_latency = total / count if count != 0 else 0

                x_values += [duration]
                y_tps_values += [tps]
                y_lat_values += [avg_latency]
                e_values += [0]

            if x_values:
                basename = os.path.basename(file)
                id = '-'.join(basename.split('-')[1:]).split('.')[0]
                plot_tps_data += [(id, x_values, y_tps_values, e_values)]
                plot_lat_data += [(id, x_values, y_lat_values, e_values)]

        self._plot(plot_tps_data, PlotType.INSPECT_TPS)
        self._plot(plot_lat_data, PlotType.INSPECT_LATENCY)



    def plot_latency_breakdown_comparison(self, workload):
        transaction_size = self.parameters.transaction_size

        # [설정] 막대 크기 및 색상
        bar_width = 250
        sub_bar_width = 80

        colors = {
            'queue': '#999999',      # 회색
            'verify': '#ff7f0e',     # 주황
            'pre_con': '#1f77b4',    # 파랑
            'cert': '#2ca02c',       # 초록
            'commit': '#d62728',     # 빨강 (통합 Commit)
        }

        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                measurements = self._load_measurement_data(filename)
                if not measurements: continue

                measurements.sort(key=lambda x: x['parameters']['load'])

                tps_points = []
                breakdown_data = []

                for m in measurements:
                    # 전역 함수 호출
                    tps = aggregate_tps(m, workload[0])
                    if tps == 0: continue

                    comps = aggregate_breakdown_components(m, workload[0])
                    if not comps: continue

                    # Commit 통합 (FPC + C-Path)
                    comps['commit_total'] = comps['commit_fpc'] + comps['commit_c']

                    print(f"[SUCCESS] Load: {m['parameters']['load']} | TPS: {tps:.2f} | Commit(Total): {comps['commit_total']:.4f}")

                    tps_points.append(tps)
                    breakdown_data.append(comps)

                if not tps_points: continue

                plt.figure(figsize=(10, 7))
                ax = plt.gca()

                # --- 데이터 플로팅 (단일 스택) ---
                for i, tps in enumerate(tps_points):
                    d = breakdown_data[i]
                    x_pos = tps

                    # 1. Main Stack: Pre-Con -> Cert -> Commit
                    b = 0
                    ax.bar(x_pos, d['pre_con'], width=bar_width, color=colors['pre_con'], edgecolor='black', label='Pre-Consensus' if i==0 else "")
                    b += d['pre_con']

                    ax.bar(x_pos, d['cert'], bottom=b, width=bar_width, color=colors['cert'], edgecolor='black', label='Certification' if i==0 else "")
                    b += d['cert']

                    ax.bar(x_pos, d['commit_total'], bottom=b, width=bar_width, color=colors['commit'], edgecolor='black', label='Commit' if i==0 else "")

                    # 2. Sub Stack (Queue -> Verify): Main 바로 왼쪽 옆에
                    x_sub = x_pos - (bar_width/2) - (sub_bar_width/2) - 10
                    b_sub = 0
                    ax.bar(x_sub, d['queue'], width=sub_bar_width, color=colors['queue'], edgecolor='black', alpha=0.8, label='Queue' if i==0 else "")
                    b_sub += d['queue']

                    ax.bar(x_sub, d['verify'], bottom=b_sub, width=sub_bar_width, color=colors['verify'], edgecolor='black', alpha=0.8, label='Verify' if i==0 else "")

                # --- 범례 및 축 설정 ---
                ax.legend(loc='upper left')
                plt.xlabel('Throughput (TPS)', fontweight='bold', fontsize=12)
                plt.ylabel('Latency (s)', fontweight='bold', fontsize=12)
                plt.title(f'Latency Breakdown (Combined) - {n} Nodes', fontweight='bold', fontsize=14)
                plt.grid(axis='y', linestyle='--', alpha=0.6)

                # X축 눈금 설정
                plt.xticks(tps_points, [f"{int(x)}" for x in tps_points])

                plot_name = f'breakdown-single-{n}-{transaction_size}.png'
                filename = os.path.join(self._make_plot_directory(), plot_name)
                plt.savefig(filename, bbox_inches='tight', dpi=300)
                print(f"Generated {filename}")

    def plot_duration(self, file, precision, workload):
        with open(file, 'r') as f:
            try:
                measurement = json.loads(f.read())
            except json.JSONDecodeError as e:
                raise PlotError(f'Failed to load file {file}: {e}')

        # [수정됨] JSON 구조 변경에 따른 Duration 파싱 로직 개선
        if 'settings' in measurement['parameters'] and 'benchmark_duration' in measurement['parameters']['settings']:
            # 최신 포맷: settings 내부에 benchmark_duration (숫자)
            total_duration = float(measurement['parameters']['settings']['benchmark_duration'])
        else:
            # 구버전 포맷 호환성 유지
            dur = measurement['parameters'].get('duration', 0)
            if isinstance(dur, dict) and 'secs' in dur:
                total_duration = float(dur['secs'])
            else:
                total_duration = float(dur)

        length = int(total_duration / precision)

        scrapers_tps_data, scrapers_lat_data = [], []
        for data in measurement['data'][workload].values():
            all_y_tps_values = [[] for _ in range(length)]
            all_y_lat_values = [[] for _ in range(length)]

            for d in data:
                count = float(d['count'])
                duration = float(d['timestamp']['secs'])
                total = float(d['sum']['secs'])

                tps = (count / duration) if duration != 0 else 0
                avg_latency = total / count if count != 0 else 0

                if duration < total_duration:
                    i = int(duration / precision)
                    all_y_tps_values[i] += [tps]
                    all_y_lat_values[i] += [avg_latency]

            aggregate_y_tps_values, aggregate_y_lat_values = [], []
            for x in all_y_tps_values:
                aggregate_y_tps_values += [
                    sum(x) / len(x) if len(x) != 0 else 0
                ]
            for x in all_y_lat_values:
                aggregate_y_lat_values += [
                    sum(x) / len(x) if len(x) != 0 else 0
                ]

            scrapers_tps_data += [aggregate_y_tps_values]
            scrapers_lat_data += [aggregate_y_lat_values]

        x_values, e_values = [], []
        y_tps_values, y_lat_values = [0]*length, [0]*length
        for i in range(length):
            x_values += [int((i*precision + (i+1)*precision)/2)]
            y_tps_values[i] = sum(x[i] for x in scrapers_tps_data)
            y_lat_values[i] = max(x[i] for x in scrapers_lat_data)
            e_values += [0]

        basename = os.path.basename(file)
        id = '-'.join(basename.split('-')[1:]).split('.')[0]

        plot_tps_data = [(id, x_values, y_tps_values, e_values)]
        plot_lat_data = [(id, x_values, y_lat_values, e_values)]
        self._plot(plot_tps_data, PlotType.DURATION_TPS)
        self._plot(plot_lat_data, PlotType.DURATION_LATENCY)

    # [Added] Plot TPS vs Average CPU Usage
    def plot_tps_cpu(self, workload, cores):
        plot_data = []
        transaction_size = self.parameters.transaction_size

        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                measurements_list = self._load_measurement_data(filename)

                x_values = []
                y_values = []
                y_err = []

                measurements_list.sort(key=lambda x: x['parameters']['load'])

                for m in measurements_list:
                    # Use the first workload specified to calculate TPS for the X-axis
                    real_tps = aggregate_tps(m, workload[0])
                    avg_cpu, stdev_cpu = aggregate_cpu_usage(m, cores=cores)

                    if real_tps > 0:
                        x_values.append(real_tps)
                        y_values.append(avg_cpu)
                        y_err.append(stdev_cpu)

                if x_values:
                    id = MeasurementId(measurements_list[0], workload[0])
                    plot_data.append((id, x_values, y_values, y_err))

        self._plot_cpu(plot_data)

    # [Added] Plot Network Bandwidth vs TPS
    def plot_bandwidth_tps(self, workload):
        plot_data_in = []
        plot_data_out = []

        transaction_size = self.parameters.transaction_size
        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                measurements = self._load_measurement_data(filename)
                measurements.sort(key=lambda x: x['parameters']['load'])

                x_values = []
                y_in = []
                y_out = []

                for m in measurements:
                    tps = aggregate_tps(m, workload[0])
                    avg_in, avg_out = aggregate_network_bandwidth(m)

                    if tps > 0:
                        x_values.append(tps)
                        y_in.append(avg_in)
                        y_out.append(avg_out)

                if x_values:
                    id = MeasurementId(measurements[0], workload[0])
                    # 에러바 없이 평균값만 그래프로 그림
                    plot_data_in.append((id, x_values, y_in, [0]*len(y_in)))
                    plot_data_out.append((id, x_values, y_out, [0]*len(y_out)))

        # 수신(Inbound) 대역폭 그래프
        self._plot_custom(plot_data_in, "Throughput (tx/s)", "Avg Inbound BW (MB/s)", "bandwidth-in.png")
        # 송신(Outbound) 대역폭 그래프
        self._plot_custom(plot_data_out, "Throughput (tx/s)", "Avg Outbound BW (MB/s)", "bandwidth-out.png")

    def _plot_custom(self, data, xlabel, ylabel, filename):
        plt.figure(figsize=(6.4, 4.8))
        markers = cycle(['o', 'v', 's', 'p', 'D', 'P'])

        for id, x, y, err in data:
            label = f"{id.nodes} Nodes"
            plt.plot(x, y, label=label, marker=next(markers), linestyle='-')

        plt.xlabel(xlabel, fontweight='bold')
        plt.ylabel(ylabel, fontweight='bold')
        plt.grid(True)
        plt.legend()

        path = os.path.join(self._make_plot_directory(), filename)
        plt.savefig(path, bbox_inches='tight')
        print(f"Generated {path}")

    def _plot_cpu(self, data):
        plt.figure(figsize=(6.4, 4.8))
        markers = cycle(['o', 'v', 's', 'p', 'D', 'P'])

        for id, x, y, err in data:
            # Label for legend: "N nodes"
            label = f"{id.nodes} Nodes"
            plt.errorbar(x, y, yerr=err, label=label, capsize=3, marker=next(markers), linestyle='-')

        plt.xlabel('Throughput (tx/s)', fontweight='bold')
        plt.ylabel('Avg CPU Usage (%)', fontweight='bold')
        plt.ylim(0, 100)
        plt.grid(True)
        plt.legend()

        filename = os.path.join(self._make_plot_directory(), 'tps-cpu.png')
        plt.savefig(filename, bbox_inches='tight')
        print(f"Generated {filename}")

    # [Added] Plot CPU Usage Over Time (Time-Series)
    def plot_cpu_over_time(self, cores):
        plot_data = []
        transaction_size = self.parameters.transaction_size

        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                measurements_list = self._load_measurement_data(filename)

                if not measurements_list: continue
                # Use the measurement with the highest load for the time-series
                measurement = max(measurements_list, key=lambda x: x['parameters']['load'])

                if 'system' not in measurement['data']: continue

                for scraper_id, data_points in measurement['data']['system'].items():
                    data_points.sort(key=lambda x: float(x['timestamp']['secs']))

                    x_time = []
                    y_cpu = []

                    for i in range(1, len(data_points)):
                        curr = data_points[i]
                        prev = data_points[i-1]

                        t1 = float(prev['timestamp']['secs'])
                        t2 = float(curr['timestamp']['secs'])

                        c1 = float(prev['cpu_accumulated_seconds'])
                        c2 = float(curr['cpu_accumulated_seconds'])

                        if t2 - t1 > 0:
                            usage_percent = (c2 - c1) / (t2 - t1) / cores * 100
                            x_time.append(t2)
                            y_cpu.append(usage_percent)

                    label = f"{n} nodes - Node {scraper_id}"
                    plot_data.append((label, x_time, y_cpu))

        self._plot_time_series(plot_data, "CPU Usage Over Time", "Time (s)", "CPU Usage (%)")

    def _plot_time_series(self, data, title, xlabel, ylabel):
        plt.figure(figsize=(10, 6))

        for label, x, y in data:
            plt.plot(x, y, label=label, marker='.', linestyle='-')

        plt.title(title)
        plt.xlabel(xlabel)
        plt.ylabel(ylabel)
        plt.ylim(0, 100)
        plt.grid(True)
        # Move legend outside if too many nodes
        plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')

        filename = os.path.join(self._make_plot_directory(), 'cpu-over-time.png')
        plt.savefig(filename, bbox_inches='tight')
        print(f"Generated {filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Sui Plotter',
        description='Simple script to plot measurement data'
    )
    parser.add_argument(
        '--dir', default='./', help='Data directory'
    )
    parser.add_argument(
        '--transaction-size', nargs='+', type=int, default=[512],
        help='The size of each transaction in the benchmark'
    )
    parser.add_argument(
        '--workload', nargs='+', type=str, default=["owned", "shared"],
        help='The type of object transaction (owned or shared)'
    )
    parser.add_argument(
        '--committee', nargs='+', type=int, default=[4],
        help='The committee sizes to plot on the same graph'
    )
    parser.add_argument(
        '--faults', nargs='+', type=int, default=[0],
        help='The number of faults to plot on the same graph'
    )
    parser.add_argument(
        '--max-latencies', nargs='+', type=float, default=[1,2],
        help='The latency cap (in seconds) for scalability graphs'
    )
    parser.add_argument(
        '--y-max', type=float, default=None,
        help='The maximum value of the y-axis for L-graphs'
    )
    parser.add_argument(
        '--legend-columns', type=int, default=1,
        help='The number of columns of the legend'
    )
    parser.add_argument('--inspect', help='The measurement file to inspect')
    parser.add_argument(
        '--precision', type=float, default=30.0,
        help='The granularity of the duration when aggregating results'
    )
    # [Added] Arguments for CPU plotting
    parser.add_argument(
        '--cores', type=int, default=32,
        help='Number of vCPUs per node for CPU usage normalization'
    )
    parser.add_argument('--plot-cpu', action='store_true', help='Plot CPU graphs')
    parser.add_argument('--plot-breakdown', action='store_true', help='Plot Latency Breakdown')
    parser.add_argument('--plot-fault', action='store_true', help='Plot Fault Time-series')

    args = parser.parse_args()

    for r in args.transaction_size:
        parameters = PlotParameters(r, args.committee, args.faults)
        plotter = Plotter(
            args.dir, parameters, args.y_max, args.legend_columns, median=False
        )
        plotter.plot_latency_throughput(args.workload)
        plotter.plot_health(args.workload)
        plotter.plot_scalability(args.max_latencies, args.workload)

        # [Added] Call CPU plotting functions if flag is set
        if args.plot_cpu:
            plotter.plot_tps_cpu(args.workload, args.cores)
            plotter.plot_cpu_over_time(args.cores)
            plotter.plot_bandwidth_tps(args.workload)
        if args.plot_breakdown:
            plotter.plot_latency_breakdown_comparison(args.workload)
        if args.plot_fault:
            plotter.plot_fault_time_series(args.workload)

    if args.inspect is not None:
        plotter.plot_inspect(args.inspect, args.workload)
        plotter.plot_duration(args.inspect, args.precision, args.workload)
