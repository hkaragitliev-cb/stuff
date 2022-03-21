#!/usr/bin/env python3

# *******************************************************
# * This demonstration script shows some operations that can be used
# * with the SDK. It is provided as-is and users should verify the
# * operations prior to executing in their environment.

# Standard library imports
import sys
import pandas as pd
from datetime import date, datetime, timedelta, timezone

# Internal library imports
from cbc_sdk import CBCloudAPI
from cbc_sdk.platform import BaseAlert


EXPORT_FILTERS = {
    "blocked_threat_category",
    "category",
    "create_time",
    "created_by_event_id",
    "device_id",
    "device_location",
    "device_name",
    "device_os",
    "device_os_version",
    "device_username",
    "first_event_time",
    "id",
    "last_event_time",
    "last_update_time",
    "legacy_alert_id",
    "not_blocked_threat_category",
    "notes_present",
    "org_key",
    "policy_applied",
    "policy_id",
    "policy_name",
    "process_name",
    "reason",
    "reason_code",
    "run_state",
    "sensor_action",
    "severity",
    "tags",
    "target_value",
    "threat_cause_actor_name",
    "threat_cause_actor_process_pid",
    "threat_cause_actor_sha256",
    "threat_cause_cause_event_id",
    "threat_cause_threat_category",
    "threat_id",
    "type",
}


def quit_script():
    """Quits script"""
    sys.exit()


def setup():
    """Text"""
    ...


def user_input(action=None):
    """Prompt user for menu choice"""
    if action == "export_results":
        choice = input('Would you like to export the results? Y/n\n')
        if choice.lower() in ['y', 'yes']:
            return True
        else:
            user_choice = user_input()
            MENU[user_choice]['function_call']()

    print('-' * 21)
    for item in MENU:
        if item == '9':
            print()
        print(f'{item} {MENU[item]["name"]}')

    choice = input('\nEnter a menu number: ')
    while choice not in MENU.keys():
        choice = input('Enter a valid choice: ')

    return choice


def handle_filters():
    """Text"""
    use_filter = input('\nExport specific fields only?: Y/n\n')
    if use_filter.lower() in ['y', 'yes']:
        print(f"{'-' * 17}\nAvailable fields\n{'-' * 17}")
        print(*EXPORT_FILTERS, sep="\n")
    else:
        return None

    custom_export_fields = []
    selected_filters = input('\nEnter the desired fields separated by space: ').split()
    for filter in selected_filters:
        if filter not in EXPORT_FILTERS:
            continue
        custom_export_fields.append(filter)

    return custom_export_fields


def export_alerts(alerts=None):
    """Text"""
    custom_export_fields = handle_filters()

    if alerts is None:
        alerts = view_alerts(view_only=False)

    export_data = []
    if custom_export_fields:
        for alert in alerts:
            filtered_alert = {}
            for item in alert._info:
                if item not in custom_export_fields:
                    continue
                filtered_alert[item] = alert._info[item]
            export_data.append(filtered_alert)
    else:
        for alert in alerts:
            export_data.append(alert._info)

    now = datetime.now()
    export_file_name = f"alerts_export_{now.strftime('%d_%m_%Y_%H-%M-%S')}.csv"

    # Prepare the data for export and save it to a file
    data_frame = pd.DataFrame(export_data)
    data_frame.to_csv(export_file_name, index=False)

    msg = f'\nExport successful: {export_file_name}\n'
    print(f"{len(msg) * '-'}{msg}{len(msg) * '-'}")

    user_choice = user_input()
    MENU[user_choice]['function_call']()


def define_time_window():
    """Text"""

    time_options = {
        "Minutely": {"1": "Past 15 Minutes", "2": "Past 30 Minutes"},
        "Hourly":   {"3": "Past Hour", "4": "Past 5 Hours"},
        "Daily":    {"5": "Today", "6": "Past 2 Days"},
        "Weekly":   {"7": "This Week", "8": "Past Two Weeks"},
        "Monthly":  {"9": "This Month"},
        "Custom":   {"10": "Custom Window"}
    }

    print(f"{'-' * 21}\nSearch Window Options\n{'-' * 21}")
    menu_items = []
    for category in time_options:
        print(f"{category}")
        for items in time_options[category]:
            print(f"  {items} {time_options[category][items]}")
            menu_items.append(items)

    choice = input('\nEnter a menu number: ')
    while choice not in menu_items:
        choice = input('Enter a valid choice: ')

    today = date.today()
    end_time = datetime.now(timezone.utc)
    if choice == '1':
        start_time = end_time - timedelta(minutes=15)
    elif choice == '2':
        start_time = end_time - timedelta(minutes=30)
    elif choice == '3':
        start_time = end_time - timedelta(minutes=60)
    elif choice == '4':
        start_time = end_time - timedelta(minutes=300)
    elif choice == '5':
        start_time = datetime.combine(today, datetime.min.time())
    elif choice == '6':
        start_time = datetime.combine(today, datetime.min.time()) - timedelta(days=1)
    elif choice == '7':
        weekday = date.weekday(today)
        start_time = datetime.combine(today, datetime.min.time()) - timedelta(days=weekday)
    elif choice == '8':
        start_time = datetime.combine(today, datetime.min.time()) - timedelta(weeks=1)
    elif choice == '9':
        month_start = today.replace(day=1)
        start_time = datetime.combine(month_start, datetime.min.time())
    elif choice == '10':
        print('\nEnter search window in UTC format(example: 2022-03-17T13:52:26.973087Z)')
        start_time = input("Start Date: ").strip()
        start_time = datetime.strptime(start_time, '%Y-%m-%dT%H:%M:%S.%fZ')
        end_time = input("End Date (press Enter to set current time): ").strip()
        if not end_time:
            end_time = datetime.now(timezone.utc)
        else:
            end_time = datetime.strptime(end_time, '%Y-%m-%dT%H:%M:%S.%fZ')

    return start_time, end_time


def view_alerts(view_only=True):
    """Text"""

    # Create cbc Instance
    cbc = CBCloudAPI(profile="default")

    # Time field and format to use
    time_field = "create_time"
    time_format = "%Y-%m-%dT%H:%M:%S.%fZ"

    start, end = define_time_window()

    # Fetch initial Alert batch
    alerts = list(cbc.select(BaseAlert)
                    .set_time_range(time_field,
                                    start=start.strftime(time_format),
                                    end=end.strftime(time_format))
                    .sort_by(time_field, "ASC"))

    # Check if 10k limit was hit and iteritevly fetch remaining
    # alerts by increasing start time to the last alert fetched
    if len(alerts) >= 10000:
        last_alert = alerts[-1]
        while True:
            new_start = datetime.strptime(last_alert.create_time, time_format) + timedelta(milliseconds=1)
            overflow = list(cbc.select(BaseAlert)
                              .set_time_range(time_field,
                                              start=new_start.strftime(time_format),
                                              end=end.strftime(time_format))
                              .sort_by(time_field, "ASC"))

            # Extend alert list with follow up alert batches
            alerts.extend(overflow)
            if len(overflow) >= 10000:
                last_alert = overflow[-1]
            else:
                break

    # Check if viewing alerts only, or exporting to csv
    if view_only:
        print(*alerts, sep="\n")
        msg = f"Fetched {len(alerts)} alerts from {start.strftime(time_format)} to {end.strftime(time_format)}"
        print(f"\n{len(msg) * '-'}\n{msg}\n{len(msg) * '-'}\n")

        export_results = user_input("export_results")
        if export_results:
            export_alerts(alerts)
    else:
        return alerts


MENU = {
    "1": {"name": "View Alerts", "function_call": view_alerts},
    "2": {"name": "Export Alerts", "function_call": export_alerts},
    #"9": {"name": "Setup", "function_call": setup},
    "0": {"name": "Quit", "function_call": quit_script}
}


def main():
    """Script entry point"""

    # Get user menu choice
    user_choice = user_input()

    # Call user specified sdk call
    MENU[user_choice]['function_call']()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user")
