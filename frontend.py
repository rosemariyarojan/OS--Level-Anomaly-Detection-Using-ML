import os
import time 
import joblib
import pandas as pd
import psutil

from plyer import notification
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURE_COLUMNS = [
    "cpu_usage",
    "memory_usage",
    "lifetime",
    "is_system"
]

MODEL_FILE = "model.pkl"
SCALER_FILE = "scaler.pkl"

LOG_FILE = f"anomaly_log_{time.strftime('%Y%m%d')}.csv"

SAFE_PROCESSES = [
    "brave.exe",
    "explorer.exe",
    "code.exe",
    "python.exe",
    "memcompression",
    "msmpeng.exe",
    "python3.13.exe",
    "snippingtool.exe",
    "svchost.exe",
    "chatgpt.exe",
    "msedgewebview2.exe",
    "dwm.exe",
    "searchindexer.exe",
    "systemsettings.exe",
    "startmenuexperiencehost.exe",
    "searchprotocolhost.exe",
    "search",
    "pwsh.exe",
    "searchfilterhost.exe",
    "shellexperiencehost.exe",
    "WmiPrvSE.exe"
]

if not os.path.exists(MODEL_FILE):
    MODE = "training"
else:
    MODE = "detection"

print(f"[+] Starting in {MODE.upper()} mode")

import glob

LOG_RETENTION_DAYS = 7
now = time.time()

for file in glob.glob("anomaly_log_*.csv"):
    if os.stat(file).st_mtime < now - LOG_RETENTION_DAYS * 86400:
        os.remove(file)

psutil.cpu_percent(interval=0.1)

process_table = {}

def collect_process_events():
    for proc in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
        try:
            pid = proc.info['pid']

            if pid == 0:
                continue

            cpu = proc.cpu_percent(interval=None)
            memory = proc.memory_info().rss
            lifetime = time.time() - proc.info['create_time']

            if pid not in process_table:
                process_table[pid] = {
                    "process_name": (proc.info['name'] or "").lower(),  
                    "cpu_usage": 0,
                    "memory_usage": 0,
                    "lifetime": 0,
                    "is_system": 0
                }

            process_table[pid]["cpu_usage"] = cpu
            process_table[pid]["memory_usage"] = memory
            process_table[pid]["lifetime"] = lifetime

            username = proc.info['username']
            if username and "SYSTEM" in username.upper():
                process_table[pid]["is_system"] = 1

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    active_pids = {p.pid for p in psutil.process_iter()}

    for pid in list(process_table.keys()):
        if pid not in active_pids:
            del process_table[pid]


def convert_to_dataframe():
    if not process_table:
        return None

    df = pd.DataFrame.from_dict(process_table, orient="index")
    df.reset_index(inplace=True)
    df.rename(columns={"index": "ProcessId"}, inplace=True)
    return df

def training_mode():
    print("[+] Collecting baseline data...")
    start_time = time.time()
    TRAINING_DURATION = 60 

    while time.time() - start_time < TRAINING_DURATION:
        collect_process_events()
        time.sleep(0.5)

    df = convert_to_dataframe()

    if df is None or df.empty:
        print("[-] Not enough data for training.")
        return

    # Ignore System Idle Process
    df = df[df["ProcessId"] != 0]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df[FEATURE_COLUMNS])

    model = IsolationForest(contamination=0.001, random_state=42)
    model.fit(X_scaled)

    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)

    print("[+] Training complete. Model saved.")

def cleanup_old_logs():
    import glob

    LOG_RETENTION_DAYS = 7
    now = time.time()

    for file in glob.glob("anomaly_log_*.csv"):
        if os.stat(file).st_mtime < now - LOG_RETENTION_DAYS * 86400:
            os.remove(file)

def detection_mode():
    print("[+] Starting detection mode...")

    model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)

    last_cleanup = time.time()
    CLEANUP_INTERVAL = 3600

    alerted_processes = set()

    while True:

        if time.time() - last_cleanup > CLEANUP_INTERVAL:
            cleanup_old_logs()
            last_cleanup = time.time()

        collect_process_events()
        df = convert_to_dataframe()

        if df is None or df.empty:
            continue
         
        X_scaled = scaler.transform(df[FEATURE_COLUMNS])
        predictions = model.predict(X_scaled)

        df["anomaly"] = [1 if p == -1 else 0 for p in predictions]
        
        anomalies = df[df["anomaly"] == 1]

        # short-lived processes only
        anomalies = anomalies[anomalies["lifetime"] < 30]

        # remove trusted processes completely
        anomalies = anomalies[
            ~anomalies["process_name"].isin(SAFE_PROCESSES)
        ]

        df.loc[df["process_name"].isin(SAFE_PROCESSES), "anomaly"] = 0

        # apply CPU rule only to remaining processes
        anomalies = anomalies[anomalies["cpu_usage"] > 200]
       
        df["timestamp"] = pd.Timestamp.now()

        temp_file = "live_results_temp.csv"
        df.to_csv(temp_file, index=False)

        for _ in range(5):
            try:
                os.replace(temp_file, "live_results.csv")
                break
            except PermissionError:
                time.sleep(0.1)

        if not anomalies.empty:

            anomalies = anomalies.copy()
            anomalies["timestamp"] = pd.Timestamp.now()

            anomalies.to_csv(
                LOG_FILE,
                mode="a",
                header=not os.path.exists(LOG_FILE),
                index=False
            )

            print("⚠️ Anomaly detected:")
            print(anomalies[["ProcessId","process_name","cpu_usage","memory_usage"]])

            for _, row in anomalies.iterrows():

                pid = row["ProcessId"]

                if pid not in alerted_processes:

                    notification.notify(
                    title="OS Anomaly Detection Alert",
                    message=f"Suspicious process detected: {row['process_name']}",
                    timeout=5
                    )

                    alerted_processes.add(pid)

if MODE == "training":
    training_mode()
    detection_mode()
else:
    detection_mode()