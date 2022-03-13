from datetime import datetime, timedelta

from boto3.dynamodb.conditions import Key

from ...common.config import Config
from .mock_decorator import mock_resource

config = Config()
try:
    enable_mocking = config.tasks.report_data_api.enable_mocking
except AttributeError:
    enable_mocking = False


def to_datetime(dt, format='%Y-%m-%d %H:%M:%S'):
    return datetime.strptime(dt, format)


def unite_timeslot(graph, work_labels, online):
    """label毎に連続時間をまとめる
    """
    slot_min = config.analysis.worktime.timeslot_interval_mins

    def convert_dic(timeslot_list, online):
        start = to_datetime(timeslot_list[0]['timeslot'])
        end = to_datetime(timeslot_list[-1]['timeslot']) \
            + timedelta(minutes=slot_min)

        return {'type': 'general' if online else 'offline',
                'start': start.strftime('%Y.%-m.%-d %H:%M'),
                'end': end.strftime('%Y.%-m.%-d %H:%M')}

    if len(work_labels) == 1:
        graph.append(convert_dic([work_labels[0]], online))
        return graph

    tmp = []
    for i, r in enumerate(work_labels):
        if i == 0:
            tmp.append(r)
        # slotが連続している場合
        elif (to_datetime(r['timeslot'])
                - to_datetime(work_labels[i - 1]['timeslot'])) \
                .total_seconds() == slot_min * 60:
            tmp.append(r)
            if i == len(work_labels) - 1:
                graph.append(convert_dic(tmp, online))
        else:
            graph.append(convert_dic(tmp, online))
            tmp = [r]
            if i == len(work_labels) - 1:
                graph.append(convert_dic(tmp, online))

    return graph


@mock_resource(enable=enable_mocking)
def get_daily_aggregate(tenant_id: str, worker_id: str, date: str, dynamodb):
    """日時の集約値を返す
    """
    dt = datetime.strptime(date, '%Y.%m.%d')
    date = dt.strftime('%Y-%m-%d')
    start_date = (dt - timedelta(days=1)).strftime('%Y-%m-%d')
    end_date = (dt + timedelta(days=1)).strftime('%Y-%m-%d')

    options = {
        'KeyConditionExpression':
            Key('worker_id').eq(worker_id)
            & Key('date').between(start_date, end_date),
        'ProjectionExpression': '#d, work_time, overtime_work_sec, \
                                 work_labels, freeze_count, security_risk',
        'ExpressionAttributeNames': {'#d': 'date'},
    }
    response = dynamodb.query(table_name=config.dynamodb.summary,
                              options=options)

    if not response['Items']:
        return []

    # 当該日
    items = [r for r in response['Items'] if r['date'] == date]
    if not items:
        return []

    items = items[0]

    # 当該日のlabel
    work_labels = [lb for r in response['Items'] for lb in r['work_labels']]
    work_labels = list(filter(
        lambda x: to_datetime(x['timeslot']).strftime('%Y-%m-%d') == date,
        work_labels
    ))

    if not work_labels:
        graph = []

    else:
        # onlineのtimeslotで終了
        for i, r in enumerate(reversed(work_labels)):
            if r['online']:
                if i == 0:
                    break
                else:
                    work_labels = work_labels[:-i]
                    break

        online = [r for r in work_labels if r['online']]
        offline = [r for r in work_labels if not r['online']]

        graph = []
        graph = unite_timeslot(graph, online, True)
        graph = unite_timeslot(graph, offline, False)
        graph = sorted(graph, key=lambda x: x['start'])

    return {
        "worktime": int(items['work_time']),
        "over_worktime": int(items['overtime_work_sec']),
        "graph": graph,
        "check_out_summary": {
            "print_count":
                int(items['security_risk']['print_risk_events_count']),
            "freeze_count": int(items['freeze_count']),
            "cloud_storage":
                int(items['security_risk']['cloud_storage_events_count']),
            "external_storage":
                int(items['security_risk']['external_storage_events_count']),
            "recruit_site_risk":
                len(items['security_risk']['recruit_site_events'])
        }
    }
