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

def ramp_up(scraper, ramp_up_threshold=120):
    ramp_up_duration, ramp_up_count = 0, 0
    ramp_up_sum, ramp_up_square_sum = 0, 0
    for data in scraper:
        duration = float(data['timestamp']['secs'])
        if duration > ramp_up_threshold:
            ramp_up_duration = duration
            ramp_up_count = float(data['count'])
            ramp_up_sum = float(data['sum']['secs'])
            ramp_up_square_sum = float(data['squared_sum']['secs'])
            break
    return ramp_up_duration, ramp_up_count, ramp_up_sum, ramp_up_square_sum

def aggregate_tps(measurement, workload):
    if workload not in measurement['data']:
        return 0

    max_duration = 0
    for data in measurement['data'][workload].values():
        ramp_up_duration, _, _, _ = ramp_up(data)
        duration = float(data[-1]['timestamp']['secs']) - ramp_up_duration
        max_duration = max(duration, max_duration)

    tps = []
    for data in measurement['data'][workload].values():
        _, ramp_up_count, _, _ = ramp_up(data)
        count = float(data[-1]['count']) - ramp_up_count
        tps += [(count / max_duration) if max_duration != 0 else 0]
    return max(tps)


def aggregate_average_latency(measurement, workload):
    if workload not in measurement['data']:
        return 0

    latency = []
    for data in measurement['data'][workload].values():
        _, ramp_up_count, ramp_up_sum, _ = ramp_up(data)
        last = data[-1]
        count = float(last['count']) - ramp_up_count
        total = float(last['sum']['secs']) - ramp_up_sum
        latency += [total / count if count != 0 else 0]
    return sum(latency) / len(latency) if latency else 0


def aggregate_stdev_latency(measurement, workload):
    if workload not in measurement['data']:
        return 0

    stdev = []
    for data in measurement['data'][workload].values():
        _, ramp_up_count, ramp_up_sum, ramp_up_square_sum = ramp_up(data)
        last = data[-1]
        count = float(last['count']) - ramp_up_count
        if count == 0:
            stdev += [0]
        else:
            latency_sum = float(last['sum']['secs']) - ramp_up_sum
            latency_square_sum = float(last['squared_sum']['secs']) - ramp_up_square_sum

            first_term = latency_square_sum / count
            second_term = (latency_sum / count)**2
            if round(first_term - second_term) != 0:
                stdev += [math.sqrt(first_term - second_term)]
            else:
                stdev += [0]
    return max(stdev)

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

def aggregate_p_latency(measurement, workload, p=50, i=-1):
    if workload not in measurement['data']:
        return 0

    latency = []
    for data in measurement['data'][workload].values():
        last = data[i]
        count = float(last['count'])
        buckets = [(float(l), c) for l, c in last['buckets'].items()]
        buckets.sort(key=lambda x: x[0])

        for l, c in buckets:
            if c >= count * p / 100:
                latency += [l]
                break

    return sum(latency) / len(latency) if latency else 0

# [Added] Function to calculate average CPU usage over a steady state period
def aggregate_cpu_usage(measurement, warm_up_sec=60, cores=32):
    if 'system' not in measurement['data']:
        return 0, 0

    node_cpu_avgs = []

    for scraper_id, data_points in measurement['data']['system'].items():
        data_points.sort(key=lambda x: float(x['timestamp']['secs']))

        if not data_points:
            continue

        start_time = float(data_points[0]['timestamp']['secs'])
        valid_points = []

        # Filter out warm-up period
        for p in data_points:
            t = float(p['timestamp']['secs'])
            if t >= start_time + warm_up_sec:
                valid_points.append(p)

        if len(valid_points) < 2:
            continue

        first = valid_points[0]
        last = valid_points[-1]

        # Calculate usage based on accumulated CPU seconds and elapsed time
        delta_cpu = float(last['cpu_accumulated_seconds']) - float(first['cpu_accumulated_seconds'])
        delta_time = float(last['timestamp']['secs']) - float(first['timestamp']['secs'])

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
    if workload not in measurement['data']:
        return {}

    # 누적 합계를 저장할 변수
    sums = {
        'queue': 0.0, 'verify': 0.0, 'pre_con': 0.0, 'cert': 0.0,
        'commit_fpc': 0.0, 'commit_c': 0.0, 'count': 0.0
    }

    # 모든 노드(scraper)의 데이터를 순회하며 마지막(steady-state) 값 합산
    # (더 정교하게 하려면 ramp_up 로직을 적용하여 delta를 구해야 함)
    valid_nodes = 0
    for data in measurement['data'][workload].values():
        if not data: continue
        last = data[-1]
        count = float(last['count'])
        if count == 0: continue

        sums['count'] += count
        sums['queue'] += float(last.get('breakdown_queue_sum', 0))
        sums['verify'] += float(last.get('breakdown_verify_sum', 0))
        sums['pre_con'] += float(last.get('breakdown_pre_consensus_sum', 0))
        sums['cert'] += float(last.get('breakdown_cert_sum', 0))
        sums['commit_fpc'] += float(last.get('breakdown_commit_fpc_sum', 0))
        sums['commit_c'] += float(last.get('breakdown_commit_c_sum', 0))
        valid_nodes += 1

    if sums['count'] == 0:
        return {}

    # 전체 평균 계산 (Total Sum / Total Count)
    avgs = {k: v / sums['count'] for k, v in sums.items() if k != 'count'}

    # Batching 시간 계산 (PreConsensus - (Queue + Verify))
    # 만약 음수가 나오면 0으로 보정
    avgs['batching'] = max(0, avgs['pre_con'] - (avgs['queue'] + avgs['verify']))

    return avgs

def aggregate_network_bandwidth(measurement, warm_up_sec=60):
    if 'system' not in measurement['data']:
        return 0, 0

    in_rates = []
    out_rates = []

    # 각 노드(scraper_id)별로 데이터를 순회
    for scraper_id, data_points in measurement['data']['system'].items():
        data_points.sort(key=lambda x: float(x['timestamp']['secs']))

        if not data_points:
            continue

        start_time = float(data_points[0]['timestamp']['secs'])
        valid_points = []

        # Warm-up 기간 제외 (CPU 로직과 동일)
        for p in data_points:
            t = float(p['timestamp']['secs'])
            if t >= start_time + warm_up_sec:
                valid_points.append(p)

        if len(valid_points) < 2:
            continue

        first = valid_points[0]
        last = valid_points[-1]

        delta_time = float(last['timestamp']['secs']) - float(first['timestamp']['secs'])

        if delta_time > 0:
            # 수신 대역폭 계산 (Bytes -> MB 변환)
            # measurement.rs에서 추가한 system_network_in_bytes 필드를 사용
            delta_in = float(last.get('system_network_in_bytes', 0)) - float(first.get('system_network_in_bytes', 0))
            in_rate_mbps = (delta_in / delta_time) / (1024 * 1024)
            in_rates.append(in_rate_mbps)

            # 송신 대역폭 계산 (Bytes -> MB 변환)
            delta_out = float(last.get('system_network_out_bytes', 0)) - float(first.get('system_network_out_bytes', 0))
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
        self.transaction_size = measurement['parameters']['benchmark_type']['transaction_size']
        self.nodes = measurement['parameters']['nodes']
        if 'Permanent' in measurement['parameters']['faults']:
            self.faults = measurement['parameters']['faults']['Permanent']['faults']
        else:
            self.faults = 0
        self.duration = measurement['parameters']['duration']
        self.machine_specs = measurement['machine_specs']
        self.commit = measurement['commit']

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
        return f'measurements-{transaction_size}-{faults}-{nodes}-{load}.json'

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

        for n in self.parameters.nodes:
            for f in self.parameters.faults:
                filename = self._file_format(transaction_size, f, n, '*')
                measurements_list = self._load_measurement_data(filename)
                if not measurements_list: continue

                # 가장 높은 Load의 실험 데이터 하나를 선택 (장애 실험은 보통 고정 Load에서 수행)
                measurement = max(measurements_list, key=lambda x: x['parameters']['load'])

                # 장애 주입 시점 추출
                fault_time = get_fault_delay(measurement)

                # 데이터 집계 (시간대별 전체 TPS 및 평균 Latency 계산)
                # 데이터 구조: measurement['data'][workload]['node_index'] = [Points...]

                if workload[0] not in measurement['data']: continue

                # 모든 노드의 데이터를 시간순으로 수집하여 글로벌 뷰 생성
                # (각 노드의 스크랩 시간이 약간씩 다를 수 있으므로 정밀도를 기준으로 버킷팅)
                precision = 1.0 # 1초 단위 집계
                time_buckets = {} # time_sec -> {'count': sum, 'latency_sum': sum, 'samples': n}

                for node_id, points in measurement['data'][workload[0]].items():
                    # 누적 카운터이므로 Delta를 구해야 함
                    points.sort(key=lambda x: float(x['timestamp']['secs']))

                    for i in range(1, len(points)):
                        prev = points[i-1]
                        curr = points[i]

                        t_prev = float(prev['timestamp']['secs'])
                        t_curr = float(curr['timestamp']['secs'])
                        dt = t_curr - t_prev

                        if dt <= 0: continue

                        # 구간의 중간 지점을 타임스탬프로 사용
                        t_mid = (t_prev + t_curr) / 2
                        bucket_key = int(t_mid / precision) * precision

                        d_count = float(curr['count']) - float(prev['count'])
                        d_sum = float(curr['sum']['secs']) - float(prev['sum']['secs'])

                        if d_count < 0: continue # 재시작 등의 경우 무시

                        if bucket_key not in time_buckets:
                            time_buckets[bucket_key] = {'tps': 0, 'lat_accum': 0, 'lat_weight': 0}

                        # TPS는 합산
                        time_buckets[bucket_key]['tps'] += (d_count / dt)

                        # Latency는 가중 평균을 위해 누적 (총 시간 / 총 개수)
                        if d_count > 0:
                            time_buckets[bucket_key]['lat_accum'] += (d_sum / d_count) # 여기선 단순 평균 합산 후 나눔
                            time_buckets[bucket_key]['lat_weight'] += 1

                # 그래프용 리스트 변환
                sorted_times = sorted(time_buckets.keys())
                if not sorted_times: continue

                x_time = []
                y_tps = []
                y_lat = []

                for t in sorted_times:
                    b = time_buckets[t]
                    x_time.append(t)
                    y_tps.append(b['tps'])
                    # 노드 간 Latency 평균
                    avg_lat = b['lat_accum'] / b['lat_weight'] if b['lat_weight'] > 0 else 0
                    y_lat.append(avg_lat)

                # --- Plotting ---
                fig, (ax1, ax2) = plt.subplots(2, 1, sharex=True, figsize=(8, 6))

                # 상단: TPS
                ax1.plot(x_time, y_tps, label=f'TPS ({n} Nodes)', color='#1f77b4', marker='.')
                ax1.set_ylabel('TPS', fontweight='bold')
                ax1.grid(True)

                # 하단: Latency
                ax2.plot(x_time, y_lat, label=f'Latency ({n} Nodes)', color='#bcbd22', marker='d')
                ax2.set_ylabel('Latency (s)', fontweight='bold')
                ax2.set_xlabel('Time (s)', fontweight='bold')
                ax2.set_yscale('log') # 로그 스케일 (이미지 참조)
                ax2.grid(True, which="both", ls="-", alpha=0.5)

                # 빨간 점선 (장애 주입 시점)
                if fault_time is not None:
                    ax1.axvline(x=fault_time, color='red', linestyle='--', linewidth=2, label='Fault Injection')
                    ax2.axvline(x=fault_time, color='red', linestyle='--', linewidth=2)

                # 범례 및 타이틀
                lines1, labels1 = ax1.get_legend_handles_labels()
                ax1.legend(lines1, labels1, loc='best')

                plt.suptitle(f'Fault Scenario Impact ({n} Nodes, {f} Faults)', fontweight='bold')

                plot_name = f'fault-series-{n}-{transaction_size}.png'
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

        # 시각화 설정
        bar_width = 200  # 막대 너비 (X축이 TPS이므로 값에 따라 조절 필요)
        sub_bar_width = bar_width * 0.4 # 서브 태스크(Verify 등) 막대 너비
        offset = bar_width / 2 + 50 # FPC와 C-Path 막대 사이 간격

        # 색상 정의
        colors = {
            'queue': '#cccccc',      # 회색
            'batching': '#1f77b4',   # 파랑 (Batching 메인)
            'verify': '#ff7f0e',     # 주황 (Verify - 서브)
            'cert': '#2ca02c',       # 초록
            'commit_fpc': '#d62728', # 빨강 (FPC Commit)
            'commit_c': '#9467bd'    # 보라 (C-Path Commit)
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
                    tps = aggregate_tps(m, workload[0])
                    if tps == 0: continue

                    comps = aggregate_breakdown_components(m, workload[0])
                    if not comps: continue

                    tps_points.append(tps)
                    breakdown_data.append(comps)

                if not tps_points: continue

                plt.figure(figsize=(10, 6))
                ax = plt.gca()

                # 데이터 플로팅
                for i, tps in enumerate(tps_points):
                    d = breakdown_data[i]

                    # X 좌표 설정 (FPC는 왼쪽, C-Path는 오른쪽)
                    x_fpc = tps - offset
                    x_c = tps + offset

                    # --- 1. FPC Stack ---
                    # Queue
                    b_q = 0
                    ax.bar(x_fpc, d['queue'], width=bar_width, color=colors['queue'], edgecolor='black', linewidth=0.5)
                    b_batch = b_q + d['queue']

                    # Batching (Verify 포함 시각화)
                    # 메인 Batching 막대
                    ax.bar(x_fpc, d['batching'] + d['verify'], bottom=b_batch, width=bar_width, color=colors['batching'], edgecolor='black', linewidth=0.5, label='Batching' if i==0 else "")

                    # Verify (서브 막대 - Batching 옆에 겹쳐서 표현)
                    # 위치: FPC 막대의 오른쪽 끝부분에 걸치게
                    ax.bar(x_fpc + bar_width/2, d['verify'], bottom=b_batch, width=sub_bar_width, color=colors['verify'], edgecolor='black', linewidth=0.5, label='Verify' if i==0 else "")

                    b_cert = b_batch + d['batching'] + d['verify']

                    # Certification
                    ax.bar(x_fpc, d['cert'], bottom=b_cert, width=bar_width, color=colors['cert'], edgecolor='black', linewidth=0.5)
                    b_commit = b_cert + d['cert']

                    # FPC Commit
                    ax.bar(x_fpc, d['commit_fpc'], bottom=b_commit, width=bar_width, color=colors['commit_fpc'], edgecolor='black', linewidth=0.5, hatch='//')

                    # --- 2. C-Path Stack ---
                    # Queue & Batching & Cert (공통 부분)
                    # 동일하게 쌓아 올림
                    ax.bar(x_c, d['queue'], width=bar_width, color=colors['queue'], edgecolor='black', linewidth=0.5)

                    # C-Path 쪽에도 Verify 표시 (선택 사항, 여기서는 Batching 통으로 표시)
                    ax.bar(x_c, d['batching'] + d['verify'], bottom=b_batch, width=bar_width, color=colors['batching'], edgecolor='black', linewidth=0.5)
                    ax.bar(x_c, d['cert'], bottom=b_cert, width=bar_width, color=colors['cert'], edgecolor='black', linewidth=0.5)

                    # C-Path Commit
                    ax.bar(x_c, d['commit_c'], bottom=b_commit, width=bar_width, color=colors['commit_c'], edgecolor='black', linewidth=0.5, hatch='..')

                # 범례 생성 (수동으로 깔끔하게)
                from matplotlib.patches import Patch
                legend_elements = [
                    Patch(facecolor=colors['queue'], edgecolor='black', label='Queue'),
                    Patch(facecolor=colors['batching'], edgecolor='black', label='Batching/Pre-con'),
                    Patch(facecolor=colors['verify'], edgecolor='black', label='Verify (Sub-task)'),
                    Patch(facecolor=colors['cert'], edgecolor='black', label='Certification'),
                    Patch(facecolor=colors['commit_fpc'], edgecolor='black', hatch='//', label='FPC Commit'),
                    Patch(facecolor=colors['commit_c'], edgecolor='black', hatch='..', label='C-Path Commit'),
                ]
                ax.legend(handles=legend_elements, loc='upper left')

                plt.xlabel('Throughput (TPS)', fontweight='bold')
                plt.ylabel('Latency (s)', fontweight='bold')
                plt.title(f'Latency Breakdown: FPC (Left) vs C-Path (Right) - {n} Nodes', fontweight='bold')
                plt.grid(axis='y', linestyle='--', alpha=0.7)

                # X축 눈금 정리
                plt.xticks(tps_points, [f"{int(x)}" for x in tps_points])

                plot_name = f'breakdown-compare-{n}-{transaction_size}.png'
                filename = os.path.join(self._make_plot_directory(), plot_name)
                plt.savefig(filename, bbox_inches='tight')
                print(f"Generated {filename}")

    def plot_duration(self, file, precision, workload):
        with open(file, 'r') as f:
            try:
                measurement = json.loads(f.read())
            except json.JSONDecodeError as e:
                raise PlotError(f'Failed to load file {file}: {e}')

        total_duration = float(measurement['parameters']['duration']['secs'])
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
                measurements = self._load_measurement_data(filename)

                x_values = []
                y_values = []
                y_err = []

                measurements.sort(key=lambda x: x['parameters']['load'])

                for m in measurements:
                    # Use the first workload specified to calculate TPS for the X-axis
                    real_tps = aggregate_tps(m, workload[0])
                    avg_cpu, stdev_cpu = aggregate_cpu_usage(m, warm_up_sec=60, cores=cores)

                    if real_tps > 0:
                        x_values.append(real_tps)
                        y_values.append(avg_cpu)
                        y_err.append(stdev_cpu)

                if x_values:
                    id = MeasurementId(measurements[0], workload[0])
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