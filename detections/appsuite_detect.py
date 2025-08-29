"""
Author: dorkerdevil
AppSuite PDF Editor Backdoor Detection Script
Detects presence of AppSuite PDF Editor backdoor via file, scheduled task, and registry indicators.
"""
import os
import sys
import winreg
import subprocess

INSTALL_PATHS = [
    os.path.expandvars(r'%LOCALAPPDATA%\Programs\PDF Editor'),
    os.path.expandvars(r'%USERPROFILE%\PDF Editor')
]
SCHEDULED_TASKS = [
    'PDFEditorScheduledTask',
    'PDFEditorUScheduledTask',
    'ShiftLaunchTask',
    'OneLaunchLaunchTask',
    'WaveBrowser-StartAtLogin'
]
RUN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Run'
RUN_VALUE = 'PDFEditorUpdater'


def check_install_paths():
    found = []
    for path in INSTALL_PATHS:
        if os.path.exists(path):
            found.append(path)
    return found

def check_scheduled_tasks():
    found = []
    for task in SCHEDULED_TASKS:
        result = subprocess.run(['schtasks', '/Query', '/TN', task], capture_output=True)
        if result.returncode == 0:
            found.append(task)
    return found

def check_run_key():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, _ = winreg.QueryValueEx(key, RUN_VALUE)
            return value
    except FileNotFoundError:
        return None

def check_log_files():
    found = []
    for path in INSTALL_PATHS:
        log1 = os.path.join(path, r'resources\app\w-electron\bin\release\default\LOG1')
        log0 = os.path.join(path, r'resources\app\w-electron\bin\release\default\LOG0')
        if os.path.exists(log1):
            found.append(log1)
        if os.path.exists(log0):
            found.append(log0)
    return found

def main():
    print('AppSuite PDF Editor Backdoor Detection')
    installs = check_install_paths()
    if installs:
        print('Suspicious install locations found:')
        for i in installs:
            print(f'  {i}')
    tasks = check_scheduled_tasks()
    if tasks:
        print('Suspicious scheduled tasks found:')
        for t in tasks:
            print(f'  {t}')
    run_val = check_run_key()
    if run_val:
        print(f'Suspicious RUN key found: {RUN_VALUE} -> {run_val}')
    logs = check_log_files()
    if logs:
        print('LOG files found:')
        for l in logs:
            print(f'  {l}')
    if not (installs or tasks or run_val or logs):
        print('No indicators found.')

if __name__ == '__main__':
    main()
