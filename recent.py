import copy
import math
from datetime import datetime, timedelta
from decimal import Decimal

from boto3.dynamodb.conditions import Attr, Key
from dateutil.relativedelta import relativedelta

from ...common.config import Config
from ...common.date_processor import date_comparator, date_range
from .lib.legal_overwork_time import (
    calc_legal_holiday_work_time, calc_legal_overtime_work_time,
)
from .mock_decorator import mock_resource

config = Config()
IN_OPERANDS_LIMIT = 100

try:
    enable_mocking = config.tasks.report_data_api.enable_mocking
except AttributeError:
    enable_mocking = False

# アラートに必要なkey
ProjectionExpression = '#d, worker_ver, worker_id, asset, \
                        work_time, overtime_work_sec, holiday_work_sec, \
                        legal_overtime_work_sec, legal_holiday_work_sec, \
                        security_risk, is_holiday, freeze_count'


def get_key_from_alert_type(alert_type: str):
    if alert_type == 'cloud-storage':
        key = 'cloud_storage_events'
    elif alert_type == 'external-storage':
        key = 'external_storage_events'
    elif alert_type == 'print':
        key = 'print_risk_events'
    elif alert_type == 'os-version':
        key = 'os_evaluation'
    elif alert_type == 'os-patch':
        key = 'os_patch_evaluation'
    elif alert_type == 'virus':
        key = 'antivirus_evaluation'
    elif alert_type == 'pattern':
        key = 'antivirus_pattern_file_evaluation'
    elif alert_type == 'overtime-work-workingday':
        key = 'overtime_work_sec'
    elif alert_type == 'recruit-site':
        key = ['security_risk', 'recruit_site_events']
    else:
        raise Exception("Invalid alert type")

    return key


def get_alerts_security_risk_and_print(items: list, alert_type: str):
    """cloud-storage, external-storage, print
    """
    key = get_key_from_alert_type(alert_type)

    security_risk_events = [
        (r['worker_id'],
         [s[0] for s in r['security_risk'][key]]) for r in items
    ]

    alerts = []
    for r in security_risk_events:
        for dt in r[1]:
            alerts.append({
                'worker_id': r[0],
                'date': datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                .strftime('%Y.%-m.%-d'),
                'time': datetime.strptime(dt, '%Y-%m-%d %H:%M:%S')
                .strftime('%H:%M:%S'),
                'event': alert_type,
                'is_custom': False
            })

    return alerts


def get_alerts_overtime_work_holiday(recent_week_items: list,
                                     thresholds: list):
    """overtime-work-holiday
    """
    alert_list = []
    for r in recent_week_items:
        if r['is_holiday']:
            continue
        try:
            thresh = next(filter(lambda x: x['worker_id'] == r['worker_id'],
                                 thresholds))
            thr = thresh['threshold']['overtime_work_holiday']
        except StopIteration and KeyError:
            thr = -1

        if r['holiday_work_sec'] > thr * 3600:
            alert_list.append({
                'worker_id': r['worker_id'],
                'date': datetime.strptime(r['date'], '%Y-%m-%d')
                .strftime('%Y.%-m.%-d'),
                'time': '-',
                'event': 'overtime-work-holiday',
                'is_custom': True if thr >= 0 else False
            })

    return alert_list


def calc_threshold(last_month_status: list):
    count = len(
        [r for r in last_month_status if r not in ['up_to_date', 'ok']]
    )
    if count == 0:
        return 2

    p = count / len(last_month_status)
    var = len(last_month_status) * p * (1 - p)

    if count > 0 and count <= 15:
        return min(count + var, 15)
    else:
        return count + var


def extract_asset_alerts(threshold: dict, recent_week_items: list,
                         worker_id: str, alert_type: str, key: str):
    """assetのアラート判定
    """
    date_list = list(set([r['date'] for r in recent_week_items
                          if r['worker_id'] == worker_id]))
    alerts = []

    for dt in date_range(min(date_list), max(date_list)):
        # レコードがない日付
        if dt not in date_list:
            continue

        yyyymm = datetime.strptime(dt, '%Y-%m-%d').strftime('%Y%m')

        # 先月データなし
        if threshold[(worker_id, yyyymm)]['threshold'] is None:
            continue

        evaluation = [r['asset'][key] for r in recent_week_items
                      if r['date'] == dt and r['worker_id'] == worker_id][0]

        if evaluation not in ['up_to_date', 'ok']:
            threshold[(worker_id, yyyymm)]['this_month_count'] += 1

            if threshold[(worker_id, yyyymm)]['this_month_count'] >= \
                    threshold[(worker_id, yyyymm)]['threshold']:
                alerts.append(
                    {
                        'worker_id': worker_id,
                        'date': datetime.strptime(dt, '%Y-%m-%d')
                        .strftime('%Y.%-m.%-d'),
                        'time': '-',
                        'event': alert_type,
                        'is_custom': False
                    }
                )

    return alerts


def get_alerts_asset(past_month_items: list, this_month_items: list,
                     recent_week_items: list, date: str, alert_type: str):
    """os-version, os-patch, virus, pattern
       n:要更新日
       1. 先月0日: >=2日
       2. 先月n(15>=n>=1)日: >=n+variance(binomial) or >=15日
       3. 先月n(n>15)日: >=n+variance(binomial)
    """
    if not recent_week_items:
        return []

    key = get_key_from_alert_type(alert_type)

    date_dt = datetime.strptime(date, '%Y-%m-%d')
    worker_ids = list(set([r['worker_id'] for r in recent_week_items]))

    threshold, alerts = {}, []

    # レポート最新日の最近1週間が月を跨ぐ
    if date_dt.day < 7:
        yyyymm_list = [date_dt.strftime('%Y%m'),
                       (date_dt - relativedelta(months=1)).strftime('%Y%m')]
    else:
        yyyymm_list = [date_dt.strftime('%Y%m')]

    for worker_id in worker_ids:
        for yyyymm in yyyymm_list:
            last_worker_ver = \
                (datetime.strptime(yyyymm, '%Y%m') - relativedelta(months=1)) \
                .strftime('%Y%m')
            last_month_status = [
                r['asset'][key] for r in past_month_items
                if r['worker_id'] == worker_id
                and r['worker_ver'] == last_worker_ver
            ]

            # 今月のアラート日までの要更新日集計
            if date_dt.day > 7:
                this_month_count = len(
                    [r for r in this_month_items
                     if r['worker_id'] == worker_id
                        and r['asset'][key] not in ['up_to_date', 'ok']]
                )
            elif date_dt.day == 7 or yyyymm == date_dt.strftime('%Y%m'):
                this_month_count = 0
            else:
                this_month_count = len(
                    [r for r in past_month_items
                     if r['worker_id'] == worker_id
                        and r['worker_ver'] == yyyymm
                        and r['date'] not in
                        [r['date'] for r in recent_week_items]
                        and r['asset'][key] not in ['up_to_date', 'ok']]
                )

            threshold[(worker_id, yyyymm)] = {
                'threshold':
                    calc_threshold(last_month_status)
                    if last_month_status else None,
                'this_month_count': this_month_count
            }

        alerts.extend(
            extract_asset_alerts(
                threshold, recent_week_items, worker_id, alert_type, key
            )
        )

    return alerts


def extract_freeze_alerts(items: list, worker_ids: list,
                          alert_start_date: str):
    alerts = []

    for worker in worker_ids:
        date_list = list(set(
            [r['date'] for r in items if r['worker_id'] == worker]
        ))

        if not date_list:
            continue

        count = 0

        for date in date_range(min(date_list), max(date_list)):
            # レコードがない日付
            if date not in date_list:
                continue

            freeze_count = [r['freeze_count'] for r in items
                            if r['date'] == date
                            and r['worker_id'] == worker][0]

            if freeze_count \
                    >= config.analysis.alerts_threshold.freeze.count:
                count += 1

            if date < alert_start_date:
                continue

            if count == config.analysis.alerts_threshold. \
                    freeze.days_in_week:
                alerts.append(
                    {
                        'worker_id': worker,
                        'date': datetime.strptime(date, '%Y-%m-%d')
                        .strftime('%Y.%-m.%-d'),
                        'time': '-',
                        'event': 'freeze',
                        'is_custom': False
                    }
                )
                # その週で1度だけ
                break

    return alerts


def get_alerts_freeze(past_week_items: list,
                      recent_week_items: list, date: str):
    """freeze
       その週（月～日）でフリーズ回数5回以上の日が3日以上 かつ
       その週でフリーズのアラートが出ていない 日にアラート
    """
    worker_ids = list(set([r['worker_id'] for r in recent_week_items]))
    date_dt = datetime.strptime(date, '%Y-%m-%d')
    alert_start_date = (date_dt - timedelta(days=6)).strftime('%Y-%m-%d')

    # レポート最新日が日曜の場合、今週分のみ
    if date_dt.weekday() == 6:
        alerts = extract_freeze_alerts(
            recent_week_items, worker_ids, alert_start_date
        )

    # レポート最新日が月火の場合、先週分のみ
    elif date_dt.weekday() < 2:
        start_date = (date_dt - timedelta(days=7 + date_dt.weekday())) \
            .strftime('%Y-%m-%d')
        end_date = (date_dt - timedelta(days=1 + date_dt.weekday())) \
            .strftime('%Y-%m-%d')

        items = [r for r in past_week_items + recent_week_items
                 # start_date <= r['date'] <= end_date
                 if date_comparator(r['date'], start_date)
                 and date_comparator(end_date, r['date'])]
        alerts = extract_freeze_alerts(items, worker_ids, alert_start_date)

    else:
        last_start_date = (date_dt - timedelta(days=7 + date_dt.weekday())) \
            .strftime('%Y-%m-%d')
        last_end_date = (date_dt - timedelta(days=1 + date_dt.weekday())) \
            .strftime('%Y-%m-%d')
        last_items = [r for r in past_week_items + recent_week_items
                      # last_start_date <= r['date'] <= last_end_date
                      if date_comparator(r['date'], last_start_date)
                      and date_comparator(last_end_date, r['date'])]

        this_start_date = (date_dt - timedelta(days=date_dt.weekday())) \
            .strftime('%Y-%m-%d')
        this_end_date = date_dt.strftime('%Y-%m-%d')
        this_items = [r for r in recent_week_items
                      # this_start_date <= r['date'] <= this_end_date
                      if date_comparator(r['date'], this_start_date)
                      and date_comparator(this_end_date, r['date'])]

        alerts = extract_freeze_alerts(
            last_items, worker_ids, alert_start_date
        ) + extract_freeze_alerts(
            this_items, worker_ids, alert_start_date
        )

    return alerts


def is_alert(sample: list, target: int, thr: dict, alert_type: str):
    """
        アラート条件（get_other_alerts）
        1. truncation ( |x - mean| > 2*rms のデータを省く)
        2. 1のsubsetからmean, rms再計算
        3. 2のmean + 2*rms より大きい、且つmean + criteria時間/回より大きい場合
    """
    if not sample:
        return False

    if alert_type == 'overtime-work-workingday':
        if 'overtime_work_workingday' in thr:
            criteria = thr['overtime_work_workingday']

            return target > criteria
        else:
            criteria = config.analysis.alerts_threshold. \
                overtime_work_workingday.increase_from_last_month
    elif alert_type == 'recruit-site':
        criteria = \
            config.analysis.alerts_threshold. \
            recruit_site.increase_from_last_month
    else:
        raise Exception("Invalid alert type")

    mean = sum(sample) / len(sample)

    if mean == 0:
        if target >= criteria:
            return True
        else:
            return False

    rms = math.sqrt(
        sum(list(map(lambda x: (x - mean) ** 2, sample))) / len(sample)
    )

    truncated = list(filter(lambda x: abs(x - mean) < 2 * rms, sample))

    if not truncated:
        return False

    mean = Decimal(sum(truncated) / len(truncated))
    rms = Decimal(math.sqrt(
        sum(list(map(lambda x: (x - mean) ** 2, truncated))) / len(truncated)
    ))

    if target > mean + 2 * rms and target > mean + Decimal(criteria):
        return True
    else:
        return False


def describe_overtime_alerts(worker_id: str, date: str,
                             items: list, alerts: list,
                             thr_overtime_work_in_month: float,
                             thr_overtime_work_in_year: float,
                             thr_total_overtime_work_in_month: float,
                             start_of_legal_working_hours: list,
                             legal_overtime_works: list, thr: dict):

    yyyymm = datetime.strptime(date, '%Y-%m-%d').strftime('%Y%m')
    alert_list = copy.copy(alerts)
    # その月でアラートが出るのは1度
    alerts_yyyymm = [
        datetime.strptime(al['date'], '%Y.%m.%d').strftime('%Y%m')
        for al in alert_list if al['worker_id'] == worker_id
    ]
    if yyyymm in alerts_yyyymm:
        return alert_list

    this_month_1st = datetime.strptime(date, '%Y-%m-%d').replace(day=1) \
        .strftime('%Y-%m-%d')

    this_month_legal_overtime_work = \
        calc_legal_overtime_work_time(
            items=[r for r in items
                   if['worker_id'] == worker_id
                   and date_comparator(r['date'], this_month_1st)
                   and date_comparator(date, r['date'])]
        )

    this_month_legal_holiday_work = \
        calc_legal_holiday_work_time(
            items=[r for r in items
                   if r['worker_id'] == worker_id
                   and date_comparator(r['date'], this_month_1st)
                   and date_comparator(date, r['date'])]
        )

    this_month_legal_work_total = \
        this_month_legal_overtime_work + this_month_legal_holiday_work

    last_month_legal_overtime_work = \
        calc_legal_overtime_work_time(
            items=[r for r in items
                   if r['worker_id'] == worker_id
                   and not date_comparator(r['date'], this_month_1st)])

    start_month = [
        ym for ym in start_of_legal_working_hours if ym < yyyymm
    ]

    if start_month:
        start_month = max(start_month)
        past_legal_overtime_work = sum([
            r['legal_overtime_work_sec'] for r in legal_overtime_works
            if r['worker_id'] == worker_id
            and start_month <= r['worker_ver'] < yyyymm])
    else:
        past_legal_overtime_work = 0

    # 2021-07以前は年間条件を使用しない
    if date_comparator(date, '2021-08-01'):
        this_year_legal_overtime_work = \
            this_month_legal_overtime_work \
            + last_month_legal_overtime_work \
            + past_legal_overtime_work
    else:
        this_year_legal_overtime_work = 0

    if (this_month_legal_overtime_work / 3600
        > thr_overtime_work_in_month
        or this_month_legal_work_total / 3600
            > thr_total_overtime_work_in_month
        or this_year_legal_overtime_work / 3600
            > thr_overtime_work_in_year):
        alert_list.append(
            {
                'worker_id': worker_id,
                'date': datetime.strptime(date, '%Y-%m-%d')
                .strftime('%Y.%-m.%-d'),
                'time': '-',
                'event': 'legal-working-hours',
                'is_custom': True if thr else False
            }
        )

    return alert_list


def get_legal_overtime_alerts(last_month_items: list, this_month_items: list,
                              recent_week_items: list, date: str,
                              legal_overtime_works: list,
                              start_of_legal_working_hours: list,
                              thresholds: list):
    """legal-working-hours
    """
    if not recent_week_items:
        return []

    date_list = list(set([r['date'] for r in recent_week_items]))
    worker_ids = list(set([r['worker_id'] for r in recent_week_items]))

    # 日曜始まりのweek number付加
    items = [dict({'week_number': datetime.strptime(r['date'], '%Y-%m-%d')
                   .strftime('%U')},
                  **r)
             for r in last_month_items + this_month_items + recent_week_items]
    alerts = []

    dummy_date = (datetime.strptime(min(date_list), '%Y-%m-%d')
                  - timedelta(days=1)).strftime('%Y-%m-%d')

    for worker_id in worker_ids:

        try:
            thresh = next(filter(lambda x: x['worker_id'] == worker_id,
                                 thresholds))
        except StopIteration:
            thresh = {}

        thr = thresh.get('threshold', {})

        thr_overtime_work_in_month = \
            thr.get('overtime_work_in_month',
                    config.analysis.alerts_threshold.
                    legal_working_hours.
                    monthly_overtime_work_hours)

        thr_overtime_work_in_year = \
            thr.get('overtime_work_in_year',
                    config.analysis.alerts_threshold.
                    legal_working_hours.
                    annual_overtime_work_hours)

        thr_total_overtime_work_in_month = \
            thr.get('total_overtime_work_in_month',
                    config.analysis.alerts_threshold.
                    legal_working_hours.
                    monthly_overtime_and_holiday_work_hours)

        for dt in date_range(dummy_date, max(date_list)):

            alerts = \
                describe_overtime_alerts(worker_id,
                                         dt,
                                         items,
                                         alerts,
                                         thr_overtime_work_in_month,
                                         thr_overtime_work_in_year,
                                         thr_total_overtime_work_in_month,
                                         start_of_legal_working_hours,
                                         legal_overtime_works,
                                         thr)

    return list(filter(
        lambda x:
            x['date'] != datetime.strptime(dummy_date,
                                           '%Y-%m-%d').strftime('%Y.%-m.%-d'),
        alerts
    ))


def get_other_alerts(past_month_items: list, recent_week_items: list,
                     date: str, alert_type: str, thresholds: list):
    """overtime-work-workingday, recruit-site
    """
    key = get_key_from_alert_type(alert_type)

    worker_ids = list(set([r['worker_id'] for r in recent_week_items]))
    past_items, alerts = {}, []

    date_dt = datetime.strptime(date, '%Y-%m-%d')

    # レポート最新日の最近1週間が月を跨ぐ場合
    if date_dt.day < 7:
        yyyymm_list = [date_dt.strftime('%Y%m'),
                       (date_dt - relativedelta(months=1)).strftime('%Y%m')]
    else:
        yyyymm_list = [date_dt.strftime('%Y%m')]

    for worker in worker_ids:

        try:
            thresh = next(filter(lambda x: x['worker_id'] == worker,
                                 thresholds))
            thr = thresh['threshold']
        except StopIteration:
            thr = {}

        for yyyymm in yyyymm_list:
            last_worker_ver = \
                (datetime.strptime(yyyymm, '%Y%m') - relativedelta(months=1)) \
                .strftime('%Y%m')
            past_items[(worker, yyyymm)] = [
                len(r[key[0]][key[1]])
                if alert_type == 'recruit-site' else r[key]
                for r in past_month_items
                if r['worker_id'] == worker
                and r['worker_ver'] == last_worker_ver
            ]

        alerts.extend([
            {
                'worker_id': worker,
                'date': datetime.strptime(r['date'], '%Y-%m-%d')
                .strftime('%Y.%-m.%-d'),
                'time': '-',
                'event': alert_type,
                'is_custom': True if thr
                and alert_type == 'overtime-work-workingday' else False
            }
            for r in recent_week_items
            if r['worker_id'] == worker
            and is_alert(
                past_items[(worker, r['worker_ver'])],
                len(r[key[0]][key[1]])
                if alert_type == 'recruit-site' else r[key],
                thr,
                alert_type
            )
        ])

    return alerts


def get_summary_for_period(tenant_id: str, worker_ids: list,
                           start_date: str, end_date: str, dynamodb):
    """ある期間のサマリを取得
    """
    items = []
    ExclusiveStartKey = None

    # IN_OPERANDS_LIMIT以上のID数の場合、条件を分割
    split_ids = [worker_ids[i:i + IN_OPERANDS_LIMIT]
                 for i in range(0, len(worker_ids), IN_OPERANDS_LIMIT)]
    FilterExpression = " | " \
        .join([f"Attr('worker_id').is_in({ids})" for ids in split_ids])

    # 1クエリでの取得制限が1MBのため、繰り返し処理
    if worker_ids:
        options = {
            'IndexName': 'tenant_id-date-index',
            'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
            & Key('date').between(start_date, end_date),
            'FilterExpression': eval(FilterExpression),
            'ProjectionExpression': ProjectionExpression,
            'ExpressionAttributeNames': {'#d': 'date'},
        }

        while True:
            if ExclusiveStartKey is None:
                response = dynamodb.query(table_name=config.dynamodb.table,
                                          options=options)
                items.extend(response['Items'])
            else:
                options['ExclusiveStartKey'] = ExclusiveStartKey
                response = dynamodb.query(table_name=config.dynamodb.table,
                                          options=options)
                items.extend(response['Items'])

            if 'LastEvaluatedKey' in response:
                ExclusiveStartKey = response['LastEvaluatedKey']
            else:
                break

    # worker_idsが空の場合、全worker対象
    else:
        options = {
            'IndexName': "tenant_id-date-index",
            'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
            & Key('date').between(start_date, end_date),
            'ProjectionExpression': ProjectionExpression,
            'ExpressionAttributeNames': {'#d': 'date'},
        }

        while True:
            if ExclusiveStartKey is None:
                response = dynamodb.query(table_name=config.dynamodb.table,
                                          options=options)
                items.extend(response['Items'])
            else:
                options['ExclusiveStartKey'] = ExclusiveStartKey
                response = dynamodb.query(table_name=config.dynamodb.table,
                                          options=options)
                items.extend(response['Items'])

            if 'LastEvaluatedKey' in response:
                ExclusiveStartKey = response['LastEvaluatedKey']
            else:
                break

    # DynamoDBの202106以前のレコードは使用しない
    return list(filter(
        lambda x: date_comparator(x['date'], '2021-07-01'), items
    ))


def get_recent_week_summary(tenant_id: str, worker_ids: list,
                            start: str, end: str, dynamodb):
    """指定日の最近1週間分のサマリを返す
    """
    return get_summary_for_period(
        tenant_id, worker_ids, start, end, dynamodb
    )


def get_past_week_summary(tenant_id: str, worker_ids: list,
                          date: str, dynamodb):
    """指定日の先週分のサマリを返す
        （指定日の先週月～指定日の7日前を返す。指定日が日曜の場合は返さない）
    """
    date = datetime.strptime(date, '%Y-%m-%d')
    if date.weekday() == 6:
        return []

    start_date = (date - timedelta(days=7 + date.weekday())) \
        .strftime('%Y-%m-%d')
    end_date = (date - timedelta(weeks=1)).strftime('%Y-%m-%d')

    return get_summary_for_period(
        tenant_id, worker_ids, start_date, end_date, dynamodb
    )


def get_last_month_summary(tenant_id: str, worker_ids: list,
                           date: str, dynamodb):
    """指定日から最近1週間が月を跨ぐ場合、先月分のサマリを返す
    """
    date = datetime.strptime(date, '%Y-%m-%d')

    # 最近1週間が月を跨がない場合
    if date.day >= 7:
        return []

    start_date = (date.replace(day=1) - relativedelta(months=1)) \
        .strftime('%Y-%m-%d')
    end_date = (date - timedelta(days=7)).strftime('%Y-%m-%d')

    return get_summary_for_period(
        tenant_id, worker_ids, start_date, end_date, dynamodb
    )


def get_past_month_summary(tenant_id: str, worker_ids: list,
                           date: str, dynamodb):
    """指定日の先月分のサマリを返す（最近1週間が月を跨ぐ場合、ふた月分）
    """
    date = datetime.strptime(date, '%Y-%m-%d')

    # 最近1週間が月を跨ぐ場合
    if date.day < 7:
        start_date = (date.replace(day=1) - relativedelta(months=2)) \
            .strftime('%Y-%m-%d')
        end_date = (date.replace(day=1) - timedelta(days=1)) \
            .strftime('%Y-%m-%d')
    else:
        start_date = (date.replace(day=1) - relativedelta(months=1)) \
            .strftime('%Y-%m-%d')
        end_date = (date.replace(day=1) - timedelta(days=1)) \
            .strftime('%Y-%m-%d')

    return get_summary_for_period(
        tenant_id, worker_ids, start_date, end_date, dynamodb
    )


def get_this_month_summary(tenant_id: str, worker_ids: list,
                           date: str, dynamodb):
    """当月1日～レポート最新日の最近1週間前までのサマリを返す
    """
    date = datetime.strptime(date, '%Y-%m-%d')

    if date.day <= 7:
        return []

    start_date = datetime(date.year, date.month, 1).strftime('%Y-%m-%d')
    end_date = (date - timedelta(days=7)).strftime('%Y-%m-%d')

    return get_summary_for_period(
        tenant_id, worker_ids, start_date, end_date, dynamodb
    )


def get_start_of_legal_working_hours(tenant_id: str, worker_ids: list,
                                     date: str, dynamodb):
    """年度開始月を取得
    """
    start_date = (datetime.strptime(date, '%Y-%m-%d') - timedelta(days=6)) \
        .strftime('%Y-%m-%d')

    split_ids = [worker_ids[i:i + IN_OPERANDS_LIMIT]
                 for i in range(0, len(worker_ids), IN_OPERANDS_LIMIT)]
    FilterExpression = " | " \
        .join([f"Attr('worker_id').is_in({ids})" for ids in split_ids])

    if worker_ids:
        options = {
            'IndexName': 'tenant_id-date-index',
            'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
            & Key('date').between(start_date, date),
            'FilterExpression': eval(FilterExpression),
            'ProjectionExpression': 'start_date_of_legal_working_hours'
        }
        response = dynamodb.query(table_name=config.dynamodb.table,
                                  options=options)
    # worker_idsが空の場合、全worker対象
    else:
        options = {
            'IndexName': "tenant_id-date-index",
            'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
            & Key('date').between(start_date, date),
            'ProjectionExpression': 'start_date_of_legal_working_hours'
        }
        response = dynamodb.query(table_name=config.dynamodb.table,
                                  options=options)

    start_of_legal_working_hours = [
        datetime.strptime(r['start_date_of_legal_working_hours'], '%Y-%m-%d')
        .strftime('%Y%m')
        for r in response['Items'] if not len(r) == 0
    ]

    return list(set(start_of_legal_working_hours))


def get_legal_overtime_works(tenant_id: str, worker_ver: str, dynamodb):
    items = []
    ExclusiveStartKey = None

    options = {
        'IndexName': "tenant_id-worker_ver-index",
        'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
        & Key('worker_ver').gte(worker_ver)
    }

    while True:
        if ExclusiveStartKey is None:
            response = dynamodb.query(
                table_name=config.dynamodb.legal_overtime,
                options=options
            )
            items.extend(response['Items'])
        else:
            options['ExclusiveStartKey'] = ExclusiveStartKey
            response = dynamodb.query(
                table_name=config.dynamodb.legal_overtime,
                options=options
            )
            items.extend(response['Items'])

        if 'LastEvaluatedKey' in response:
            ExclusiveStartKey = response['LastEvaluatedKey']
        else:
            break

    return items


def normlized_alerts(alerts: list):
    # 日付ごとにアラートをgroup by
    formatted = []
    for a in alerts:
        if a['date'] not in [f.get("date_label") for f in formatted]:
            formatted.append({
                "date_label": a['date'],
                "alerts": []
            })
        for f in formatted:
            if f['date_label'] == a['date']:
                f['alerts'].append(a)

    # 時間とアルファベットで逆順ソート
    def priority(c):
        return c == '-'

    for f in formatted:
        f['alerts'] = sorted(f['alerts'],
                             key=lambda x: [priority(x['time']),
                                            x['time'], x['worker_id'],
                                            x['event']],
                             reverse=True)

    # 日付で逆順ソート
    formatted = sorted(formatted,
                       key=lambda x: [datetime.strptime(x['date_label'],
                                                        '%Y.%m.%d')],
                       reverse=True)

    return {"data": formatted}


@mock_resource(enable=enable_mocking)
def get_recent_week_alerts(tenant_id: str, worker_ids: list,
                           filter_type: list, start: str, end: str, dynamodb):
    """早期化の最近一週間のアラート一覧を返す
    """
    thresholds = return_thresholds(tenant_id, worker_ids, end, dynamodb)

    # filter_typeが空ならall
    if not filter_type:
        filter_type = [
            'overtime-work-holiday',
            'cloud-storage',
            'external-storage',
            'print',
            'overtime-work-workingday',
            'legal-working-hours',
            'os-version',
            'os-patch',
            'virus',
            'pattern',
            'freeze',
            'recruit-site'
        ]

    items = dict.fromkeys(['recent_week_items', 'last_month_items',
                           'past_month_items', 'this_month_items',
                           'past_week_items', 'start_of_legal_working_hours',
                           'legal_overtime_works', 'latest_day'])

    alert_start_date = datetime.strptime(start, '%Y.%m.%d') \
        .strftime('%Y-%m-%d')
    items['latest_day'] = datetime.strptime(end, '%Y.%m.%d') \
        .strftime('%Y-%m-%d')

    # 1週間のデータを取得
    items['recent_week_items'] = get_recent_week_summary(
        tenant_id, worker_ids, alert_start_date, items['latest_day'], dynamodb
    )

    # 過去分のデータが必要な場合は取得
    if set(filter_type).intersection({"overtime-work-workingday",
                                      "os-version", "os-patch", "virus",
                                      "pattern", "recruit-site"}):
        items['past_month_items'] = get_past_month_summary(
            tenant_id, worker_ids, items['latest_day'], dynamodb)

        if set(filter_type).intersection({"os-version", "os-patch",
                                          "virus", "pattern"}):
            items['this_month_items'] = get_this_month_summary(
                tenant_id, worker_ids, items['latest_day'], dynamodb)

    if set(filter_type).intersection({"freeze"}):
        items['past_week_items'] = get_past_week_summary(
            tenant_id, worker_ids, items['latest_day'], dynamodb)

    if set(filter_type).intersection({"legal-working-hours"}):
        items['start_of_legal_working_hours'] = \
            get_start_of_legal_working_hours(
                tenant_id, worker_ids, items['latest_day'], dynamodb)

        items['last_month_items'] = get_last_month_summary(
            tenant_id, worker_ids, items['latest_day'], dynamodb)
        # 他のアラート用途で取得していない場合
        if items['this_month_items'] is None:
            items['this_month_items'] = get_this_month_summary(
                tenant_id, worker_ids, items['latest_day'], dynamodb)

        if items['start_of_legal_working_hours']:
            worker_ver = min(items['start_of_legal_working_hours'])
            items['legal_overtime_works'] = \
                get_legal_overtime_works(tenant_id, worker_ver, dynamodb)
        else:
            pass

    alert_generator = {
        'overtime-work-holiday':
            lambda x: get_alerts_overtime_work_holiday(x['recent_week_items'],
                                                       thresholds),
        'cloud-storage':
            lambda x: get_alerts_security_risk_and_print(
                x['recent_week_items'], 'cloud-storage'
            ),
        'external-storage':
            lambda x: get_alerts_security_risk_and_print(
                x['recent_week_items'], 'external-storage'
            ),
        'print':
            lambda x: get_alerts_security_risk_and_print(
                x['recent_week_items'], 'print'
            ),
        'overtime-work-workingday':
            lambda x: get_other_alerts(
                x['past_month_items'], x['recent_week_items'],
                x['latest_day'], 'overtime-work-workingday', thresholds
            ),
        'legal-working-hours':
            lambda x: get_legal_overtime_alerts(
                x['last_month_items'], x['this_month_items'],
                x['recent_week_items'], x['latest_day'],
                x['legal_overtime_works'], x['start_of_legal_working_hours'],
                thresholds
            ),
        'os-version':
            lambda x: get_alerts_asset(
                x['past_month_items'], x['this_month_items'],
                x['recent_week_items'], x['latest_day'], 'os-version'
            ),
        'os-patch':
            lambda x: get_alerts_asset(
                x['past_month_items'], x['this_month_items'],
                x['recent_week_items'], x['latest_day'], 'os-patch'
            ),
        'virus':
            lambda x: get_alerts_asset(
                x['past_month_items'], x['this_month_items'],
                x['recent_week_items'], x['latest_day'], 'virus'
            ),
        'pattern':
            lambda x: get_alerts_asset(
                x['past_month_items'], x['this_month_items'],
                x['recent_week_items'], x['latest_day'], 'pattern'
            ),
        'freeze':
            lambda x: get_alerts_freeze(
                x['past_week_items'], x['recent_week_items'], x['latest_day']
            ),
        'recruit-site':
            lambda x: get_other_alerts(
                x['past_month_items'], x['recent_week_items'],
                x['latest_day'], 'recruit-site', thresholds
            )
    }

    alerts = []
    for filt in filter_type:
        alerts.extend(alert_generator[filt](items))

    return normlized_alerts(alerts)


def return_thresholds(tenant_id: str, worker_ids: list, date: str, dynamodb):

    if worker_ids:
        options = {
            'IndexName': 'tenant_id-date-index',
            'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
            & Key('date').eq(date),
            'FilterExpression': Attr('worker_id').is_in(worker_ids)
        }

    else:
        options = {
            'IndexName': 'tenant_id-date-index',
            'KeyConditionExpression': Key('tenant_id').eq(tenant_id)
            & Key('date').eq(date)
        }

    response = dynamodb.query(table_name=config.dynamodb.alert_threshold,
                              options=options)

    return response['Items']
