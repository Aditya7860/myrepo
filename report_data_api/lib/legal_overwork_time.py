import itertools
from datetime import datetime
from typing import List
from ..table import TableRecord


def calc_legal_overtime_work_time(items: list):
    legal_overtime_work_sec = 0

    for week_number, weekly_ite in itertools.groupby(
            sorted(items, key=lambda x: (x['week_number'], x['date'])),
            key=lambda x: x['week_number']):
        weekly_record = list(weekly_ite)
        weekly_legal_overtime_work = 0
        daily_legal_overtime_work = 0

        for r in weekly_record:
            if 'legal_overtime_work_sec' in r:
                daily_legal_overtime_work += r['legal_overtime_work_sec']
                weekly_legal_overtime_work += \
                    min(r['work_time'], 8 * 60 * 60)
            else:
                if datetime.strptime(r['date'], '%Y-%m-%d').weekday() == 6:
                    continue
                else:
                    daily_legal_overtime_work += \
                        max(r['work_time'] - 8 * 60 * 60, 0)
                    weekly_legal_overtime_work += \
                        min(r['work_time'], 8 * 60 * 60)

        weekly_legal_overtime_work = \
            max(weekly_legal_overtime_work - 40 * 60 * 60, 0)

        # 最新週の最新日が土曜でない場合は含めない
        if week_number == weekly_record[-1]['week_number'] \
            and datetime.strptime(weekly_record[-1]['date'],
                                  '%Y-%m-%d').weekday() != 5:
            weekly_legal_overtime_work = 0

        legal_overtime_work_sec += \
            daily_legal_overtime_work + weekly_legal_overtime_work

    return legal_overtime_work_sec


def calc_legal_holiday_work_time(items: dict):
    return sum(
        r['legal_holiday_work_sec']
        if 'legal_holiday_work_sec' in r
        else r['holiday_work_sec']
        * (datetime.strptime(r['date'], '%Y-%m-%d').weekday() == 6)
        for r in items
    )
