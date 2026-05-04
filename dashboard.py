import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timezone
import os
import json
import time
import io
import re

try:
    import boto3
except ImportError:
    boto3 = None

# ─────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NLP Log Anomaly Detection",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────
# S3 SETTINGS
# Keep these aligned with your AWS pipeline. Values can be overridden using
# Streamlit Secrets or environment variables.
# ─────────────────────────────────────────────────────────────
DEFAULT_BUCKET_NAME = "logbert-dashboard-alerts-914115115831"
DEFAULT_S3_PREFIX = "logbert-alerts/"
DEFAULT_AWS_REGION = "ap-southeast-2"
EMAIL_THRESHOLD = 11.8


def get_config_value(key: str, default: str = "") -> str:
    """Read config from Streamlit secrets first, then environment variables."""
    try:
        value = st.secrets.get(key, None)
        if value not in [None, ""]:
            return value
    except Exception:
        pass
    return os.getenv(key, default)

# ─────────────────────────────────────────────────────────────
# CUSTOM CSS  — kept from old dashboard
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1a1a2e;
        padding: 0.5rem 0;
    }
    .sub-header {
        color: #555;
        font-size: 0.95rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background: #f8f9fa;
        border-radius: 12px;
        padding: 1rem 1.2rem;
        border-left: 5px solid #4361ee;
        margin-bottom: 0.5rem;
    }
    .critical-badge { color: #d62828; font-weight: 700; }
    .high-badge     { color: #f77f00; font-weight: 700; }
    .medium-badge   { color: #e9c46a; font-weight: 700; }
    .low-badge      { color: #2a9d8f; font-weight: 700; }
    .normal-badge   { color: #6c757d; font-weight: 600; }
    .alert-box {
        background: #fff3cd;
        border: 1px solid #ffc107;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        margin: 0.5rem 0;
    }
    .alert-critical {
        background: #fce4e4;
        border: 1px solid #d62828;
    }
    .stDataFrame { border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# THREAT SCORING LOGIC  — kept from old dashboard for uploaded/default files
# S3 LogBERT alerts already include score, so S3 rows use that score directly.
# ─────────────────────────────────────────────────────────────
HIGH_KEYWORDS   = ['break-in', 'unauthorized', 'attack', 'breach', 'fatal',
                   'corrupt', 'illegal', 'privilege escalation', 'rapid successive']
MEDIUM_KEYWORDS = ['failed', 'invalid', 'refused', 'denied', 'error',
                   'failure', 'authentication failure', 'check pass user unknown',
                   'exceeded', 'blacklisted']
LOW_KEYWORDS    = ['exception', 'unknown', 'timeout', 'abort', 'warning',
                   'bad', 'wrong', 'dropping', 'spoofing']


def compute_threat_score(log_text: str) -> int:
    text = str(log_text).lower()
    score = 0
    for kw in HIGH_KEYWORDS:
        if kw in text:
            score += 16
    for kw in MEDIUM_KEYWORDS:
        if kw in text:
            score += 10
    for kw in LOW_KEYWORDS:
        if kw in text:
            score += 4
    return min(score, 100)


def severity_label(score: float) -> str:
    """Severity scale for LogBERT anomaly scores, not the old 0-100 keyword score scale."""
    try:
        score = float(score)
    except Exception:
        score = 0.0

    if score > 14:
        return "CRITICAL"
    elif score > EMAIL_THRESHOLD:
        return "HIGH"
    elif score > 9:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "NORMAL"


def normalise_severity(value, score: float = 0) -> str:
    """Convert S3 alert_level values into the old dashboard severity labels."""
    if pd.isna(value):
        return severity_label(score)

    text = str(value).strip().upper()
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "NORMAL": "NORMAL",
        "INFO": "NORMAL",
        "INFORMATION": "NORMAL",
        "WARNING": "LOW",
        "WARN": "LOW",
        "EMAIL": "LOW",
        "EMAIL_ALERT": "LOW",
        "OPENAI_REQUIRED": "LOW",
        "RECOMMENDATION_REQUIRED": "LOW",
        "ANOMALY": "LOW",
        "ALERT": "LOW",
    }
    return mapping.get(text, severity_label(score))


SEVERITY_COLORS = {
    "CRITICAL": "#d62828",
    "HIGH":     "#f77f00",
    "MEDIUM":   "#e9c46a",
    "LOW":      "#2a9d8f",
    "NORMAL":   "#adb5bd",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NORMAL"]

# ─────────────────────────────────────────────────────────────
# LOG TEXT NORMALISER  — kept from old dashboard
# ─────────────────────────────────────────────────────────────
def normalise_log(text: str) -> str:
    text = str(text)
    text = re.sub(r'\w+\[\d+\]:', '', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'ip_addr', text)
    text = re.sub(r'\bport\s+\d+', 'port_num', text)
    text = re.sub(r'blk_[-\d]+', 'block_id', text)
    text = re.sub(r'\b0x[0-9a-fA-F]+\b', 'hex_val', text)
    text = re.sub(r'\b\d{5,}\b', 'num', text)
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s_]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# ─────────────────────────────────────────────────────────────
# AWS SNS ALERT  — kept from old dashboard
# ─────────────────────────────────────────────────────────────
def send_sns_alert(subject: str, message: str,
                   topic_arn: str, region: str,
                   aws_key: str = "", aws_secret: str = "") -> dict:
    try:
        if boto3 is None:
            return {"success": False, "message": "boto3 not installed. Run: pip install boto3"}

        kwargs = dict(region_name=region)
        if aws_key and aws_secret:
            kwargs["aws_access_key_id"] = aws_key
            kwargs["aws_secret_access_key"] = aws_secret

        client = boto3.client("sns", **kwargs)
        response = client.publish(
            TopicArn=topic_arn,
            Subject=subject[:100],
            Message=message
        )
        return {"success": True, "message": f"SNS MessageId: {response['MessageId']}"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def build_alert_message(row: pd.Series) -> str:
    return (
        f"🚨 SECURITY ALERT — {row['severity']} THREAT DETECTED\n"
        f"{'='*50}\n"
        f"Timestamp   : {row.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
        f"Threat Score: {row['threat_score']} / 100\n"
        f"Severity    : {row['severity']}\n"
        f"Source      : {row.get('source', 's3_logbert_alert')}\n"
        f"S3 Key      : {row.get('s3_key', '')}\n\n"
        f"Log Message :\n{row['log_message']}\n"
        f"{'='*50}\n"
        f"Action Required: Review this log entry immediately.\n"
        f"Generated by COIT20265 NLP Anomaly Detection System"
    )

# ─────────────────────────────────────────────────────────────
# DATA LOADERS
# ─────────────────────────────────────────────────────────────
def _list_s3_json_objects(s3_client, bucket_name: str, prefix: str):
    continuation_token = None
    while True:
        kwargs = {"Bucket": bucket_name, "Prefix": prefix}
        if continuation_token:
            kwargs["ContinuationToken"] = continuation_token
        response = s3_client.list_objects_v2(**kwargs)
        for obj in response.get("Contents", []):
            key = obj.get("Key", "")
            if key.endswith(".json"):
                yield obj
        if response.get("IsTruncated"):
            continuation_token = response.get("NextContinuationToken")
        else:
            break


@st.cache_data(ttl=60, show_spinner=False)
def load_alerts_from_s3(bucket_name: str, prefix: str, region: str) -> pd.DataFrame:
    """Load LogBERT JSON alert files from S3 and convert them to old dashboard columns."""
    if boto3 is None:
        raise ImportError("boto3 is not installed. Run: pip install boto3")

    aws_access_key = get_config_value("AWS_ACCESS_KEY_ID")
    aws_secret_key = get_config_value("AWS_SECRET_ACCESS_KEY")
    aws_session_token = get_config_value("AWS_SESSION_TOKEN")

    client_kwargs = {"region_name": region}
    if aws_access_key and aws_secret_key:
        client_kwargs["aws_access_key_id"] = aws_access_key
        client_kwargs["aws_secret_access_key"] = aws_secret_key
    if aws_session_token:
        client_kwargs["aws_session_token"] = aws_session_token

    s3 = boto3.client("s3", **client_kwargs)

    alerts = []
    for obj in _list_s3_json_objects(s3, bucket_name, prefix):
        key = obj["Key"]
        try:
            file_obj = s3.get_object(Bucket=bucket_name, Key=key)
            content = file_obj["Body"].read().decode("utf-8")
            alert = json.loads(content)
            alert["s3_key"] = key
            alert["last_modified"] = obj.get("LastModified")
            alerts.append(alert)
        except Exception as e:
            print(f"Skipping broken S3 object {key}: {e}")

    if not alerts:
        return pd.DataFrame()

    df = pd.DataFrame(alerts)

    # Score compatibility: S3 LogBERT files normally use `score`.
    if "score" in df.columns:
        df["threat_score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0)
    elif "anomaly_score" in df.columns:
        df["threat_score"] = pd.to_numeric(df["anomaly_score"], errors="coerce").fillna(0)
    elif "threat_score" in df.columns:
        df["threat_score"] = pd.to_numeric(df["threat_score"], errors="coerce").fillna(0)
    else:
        df["threat_score"] = 0

    # Severity compatibility: keep old labels/colors even when S3 uses custom alert_level.
    source_severity = df["alert_level"] if "alert_level" in df.columns else None
    if source_severity is not None:
        df["severity"] = [normalise_severity(level, score) for level, score in zip(source_severity, df["threat_score"])]
    elif "severity" in df.columns:
        df["severity"] = [normalise_severity(level, score) for level, score in zip(df["severity"], df["threat_score"])]
    else:
        df["severity"] = df["threat_score"].apply(severity_label)

    # Timestamp compatibility: prefer alert timestamp if present; otherwise use S3 LastModified.
    timestamp_candidates = ["timestamp", "created_at", "event_time", "last_modified"]
    timestamp_col = next((c for c in timestamp_candidates if c in df.columns), None)
    if timestamp_col:
        df["timestamp"] = pd.to_datetime(df[timestamp_col], errors="coerce")
    else:
        df["timestamp"] = pd.Timestamp.now(tz="UTC")
    df["timestamp"] = df["timestamp"].fillna(pd.Timestamp.now(tz="UTC"))

    # Log message compatibility: S3 files may contain sample_logs as a list.
    if "sample_logs" in df.columns:
        df["log_message"] = df["sample_logs"].apply(
            lambda logs: " | ".join(map(str, logs)) if isinstance(logs, list) else str(logs)
        )
    elif "log_message" in df.columns:
        df["log_message"] = df["log_message"].astype(str)
    elif "message" in df.columns:
        df["log_message"] = df["message"].astype(str)
    else:
        df["log_message"] = ""

    df["cleaned_log"] = df["log_message"].apply(normalise_log)

    # Source compatibility for old source breakdown chart.
    if "source" not in df.columns or df["source"].isna().all():
        df["source"] = "s3_logbert_alerts"
    df["source"] = df["source"].fillna("s3_logbert_alerts").astype(str)

    # Optional fields used in tables/detail view.
    for col in [
        "window_id", "lines", "start_line", "end_line", "alert_type", "reason",
        "recommendation_required", "s3_key", "sample_logs", "alert_level"
    ]:
        if col not in df.columns:
            df[col] = ""

    if "label" not in df.columns:
        df["label"] = df["threat_score"].apply(lambda s: 1 if s > 0 else 0)

    return df.sort_values("timestamp", ascending=False).reset_index(drop=True)


@st.cache_data(show_spinner=False)
def load_and_score(uploaded_file_bytes: bytes, filename: str) -> pd.DataFrame:
    """Load CSV or raw log, score every entry, return scored DataFrame."""
    if filename.endswith(".csv"):
        df = pd.read_csv(io.BytesIO(uploaded_file_bytes))
        log_col = None
        for candidate in ["log_message", "cleaned_log", "Content", "message", "log"]:
            if candidate in df.columns:
                log_col = candidate
                break
        if log_col is None:
            log_col = df.select_dtypes(include="object").columns[0]
        df = df.rename(columns={log_col: "log_message"})
    else:
        lines = uploaded_file_bytes.decode("utf-8", errors="ignore").splitlines()
        df = pd.DataFrame({"log_message": [l.strip() for l in lines if l.strip()]})

    if "timestamp" not in df.columns:
        base = datetime.now().replace(second=0, microsecond=0)
        df["timestamp"] = [
            (base - pd.Timedelta(seconds=i * 30)).strftime("%Y-%m-%d %H:%M:%S")
            for i in range(len(df) - 1, -1, -1)
        ]

    df["cleaned_log"] = df["log_message"].apply(normalise_log)
    df["threat_score"] = df["cleaned_log"].apply(compute_threat_score)
    df["severity"] = df["threat_score"].apply(severity_label)

    if "source" not in df.columns:
        df["source"] = "uploaded"
    if "label" not in df.columns:
        df["label"] = df["threat_score"].apply(lambda s: 1 if s > 0 else 0)

    return df.reset_index(drop=True)


def load_default_dataset() -> pd.DataFrame:
    """Load full_dataset_final.csv if it exists alongside dashboard.py."""
    path = os.path.join(os.path.dirname(__file__), "full_dataset_final.csv")
    if not os.path.exists(path):
        return None
    df = pd.read_csv(path)
    if "cleaned_log" in df.columns and "log_message" not in df.columns:
        df = df.rename(columns={"cleaned_log": "log_message"})
    if "log_message" not in df.columns:
        log_col = df.select_dtypes(include="object").columns[0]
        df = df.rename(columns={log_col: "log_message"})
    df["threat_score"] = df["log_message"].apply(compute_threat_score)
    df["severity"] = df["threat_score"].apply(severity_label)
    df["cleaned_log"] = df["log_message"].apply(normalise_log)
    if "timestamp" not in df.columns:
        base = datetime.now().replace(second=0, microsecond=0)
        df["timestamp"] = [
            (base - pd.Timedelta(seconds=i * 30)).strftime("%Y-%m-%d %H:%M:%S")
            for i in range(len(df) - 1, -1, -1)
        ]
    if "source" not in df.columns:
        df["source"] = "project_dataset"
    if "label" not in df.columns:
        df["label"] = df["threat_score"].apply(lambda s: 1 if s > 0 else 0)
    return df.reset_index(drop=True)

# ─────────────────────────────────────────────────────────────
# CHARTS  — same visualisations/graphs as old dashboard
# ─────────────────────────────────────────────────────────────
def chart_severity_donut(df: pd.DataFrame):
    counts = df["severity"].value_counts().reindex(SEVERITY_ORDER).dropna()
    if counts.empty:
        counts = pd.Series(dtype=int)
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        hole=0.55,
        marker_colors=[SEVERITY_COLORS[s] for s in counts.index],
        textinfo="label+percent",
        hovertemplate="%{label}: %{value} logs<extra></extra>",
    ))
    fig.update_layout(
        title="Severity Distribution",
        showlegend=False,
        margin=dict(t=40, b=10, l=10, r=10),
        height=280,
    )
    return fig


def chart_threat_score_hist(df: pd.DataFrame):
    fig = px.histogram(
        df, x="threat_score", nbins=30,
        color_discrete_sequence=["#4361ee"],
        title="Threat Score Distribution",
        labels={"threat_score": "Threat Score", "count": "Log Count"},
    )
    fig.add_vline(x=9, line_dash="dash", line_color="#e9c46a", annotation_text="Medium > 9")
    fig.add_vline(x=EMAIL_THRESHOLD, line_dash="dash", line_color="#f77f00", annotation_text=f"Email/High > {EMAIL_THRESHOLD}")
    fig.add_vline(x=14, line_dash="dash", line_color="#d62828", annotation_text="Critical > 14")
    fig.update_layout(height=300, margin=dict(t=40, b=20, l=20, r=20))
    return fig


def chart_score_over_time(df: pd.DataFrame):
    dft = df.copy()
    dft["timestamp"] = pd.to_datetime(dft["timestamp"], errors="coerce")
    dft = dft.dropna(subset=["timestamp"]).sort_values("timestamp")
    fig = px.scatter(
        dft, x="timestamp", y="threat_score",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Threat Score Over Time",
        labels={"threat_score": "Threat Score", "timestamp": "Time"},
        hover_data=["log_message"],
        category_orders={"severity": SEVERITY_ORDER},
    )
    fig.update_layout(height=320, margin=dict(t=40, b=20, l=20, r=20))
    return fig


def chart_source_breakdown(df: pd.DataFrame):
    if "source" not in df.columns:
        return None
    grp = (df.groupby(["source", "severity"])
             .size()
             .reset_index(name="count"))
    fig = px.bar(
        grp, x="source", y="count", color="severity",
        color_discrete_map=SEVERITY_COLORS,
        title="Severity Breakdown by Log Source",
        labels={"count": "Log Count", "source": "Source"},
        category_orders={"severity": SEVERITY_ORDER},
        barmode="stack",
    )
    fig.update_layout(height=300, margin=dict(t=40, b=20, l=20, r=20))
    return fig


def chart_top_threats(df: pd.DataFrame, n=10):
    top = df.nlargest(n, "threat_score")[["log_message", "threat_score", "severity"]].copy()
    top["short_log"] = top["log_message"].apply(lambda x: str(x)[:60] + "…" if len(str(x)) > 60 else str(x))
    fig = px.bar(
        top.sort_values("threat_score"),
        x="threat_score", y="short_log",
        color="severity",
        color_discrete_map=SEVERITY_COLORS,
        orientation="h",
        title=f"Top {n} Highest Threat Logs",
        labels={"threat_score": "Score", "short_log": ""},
        category_orders={"severity": SEVERITY_ORDER},
    )
    fig.update_layout(height=380, margin=dict(t=40, b=20, l=10, r=10), showlegend=False)
    return fig

# ─────────────────────────────────────────────────────────────
# SIDEBAR  — old sidebar visual layout, with S3 added as the default source
# ─────────────────────────────────────────────────────────────
with st.sidebar:

    st.markdown("### 🔐 NLP Log Anomaly Detection")
    st.markdown("**COIT20265 · CQUniversity**")
    st.markdown("Project Client: Dr Fariza Sabrina")
    st.divider()

    st.markdown("#### 📂 Data Source")
    data_mode = st.radio(
        "Choose input:",
        ["Amazon S3 LogBERT alerts", "Upload file", "Use project dataset"],
        index=0
    )

    uploaded_file = None
    bucket_name = get_config_value("S3_BUCKET_NAME", DEFAULT_BUCKET_NAME)
    s3_prefix = get_config_value("S3_PREFIX", DEFAULT_S3_PREFIX)
    aws_region_default = get_config_value("AWS_DEFAULT_REGION", DEFAULT_AWS_REGION)

    if data_mode == "Amazon S3 LogBERT alerts":
        bucket_name = st.text_input("S3 Bucket", value=bucket_name)
        s3_prefix = st.text_input("S3 Prefix", value=s3_prefix)
        aws_region_default = st.text_input("AWS Region", value=aws_region_default)
        if st.button("🔄 Refresh S3 data"):
            st.cache_data.clear()
            st.rerun()
        st.caption("Uses Streamlit Secrets, environment variables, AWS profile, or IAM role credentials.")
    elif data_mode == "Upload file":
        uploaded_file = st.file_uploader(
            "Upload a CSV or .log file",
            type=["csv", "log", "txt"],
            help="CSV columns recognised: log_message, cleaned_log, Content, message\n"
                 "Raw .log files are parsed line-by-line."
        )

    st.divider()
    st.markdown("#### ⚙️ Alert Settings")
    alert_enabled = st.checkbox("Enable AWS SNS Alerts", value=False)

    sns_topic_arn = ""
    sns_region = aws_region_default
    aws_key = ""
    aws_secret = ""

    if alert_enabled:
        sns_topic_arn = st.text_input("SNS Topic ARN",
                                      placeholder="arn:aws:sns:ap-southeast-2:123456789012:security-alerts")
        sns_region = st.text_input("AWS Region for SNS", value=aws_region_default)
        aws_key = st.text_input("AWS Access Key ID", type="password", value="")
        aws_secret = st.text_input("AWS Secret Access Key", type="password", value="")
        st.caption("Leave keys blank when using IAM role / default AWS credentials.")

    st.divider()
    st.markdown("#### 🔎 Filters")
    score_threshold = st.slider("Min Threat Score", 0.0, 100.0, 0.0, step=0.1)
    severity_filter = st.multiselect(
        "Severity levels to show",
        SEVERITY_ORDER,
        default=SEVERITY_ORDER
    )

    st.divider()
    st.markdown("#### ℹ️ LogBERT Scoring Legend")
    ranges = {
        "CRITICAL": "> 14",
        "HIGH": f"> {EMAIL_THRESHOLD} to 14",
        "MEDIUM": f"> 9 to {EMAIL_THRESHOLD}",
        "LOW": "> 0 to 9",
        "NORMAL": "0",
    }
    for sev in SEVERITY_ORDER:
        col = SEVERITY_COLORS[sev]
        st.markdown(f"<span style='color:{col};font-weight:700'>■ {sev}</span> — LogBERT score {ranges[sev]}",
                    unsafe_allow_html=True)
    st.caption(f"Email / action threshold: LogBERT score > {EMAIL_THRESHOLD}")

# ─────────────────────────────────────────────────────────────
# MAIN PANEL  — same visual style as old dashboard
# ─────────────────────────────────────────────────────────────
st.markdown('<div class="main-header">🔐 NLP Log Anomaly Detection Dashboard</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">COIT20265 · CQUniversity Australia · Dr Fariza Sabrina</div>', unsafe_allow_html=True)

# ── Load data ──────────────────────────────────────────────
df_full = None

if data_mode == "Amazon S3 LogBERT alerts":
    st.info(f"Reading LogBERT alerts from `s3://{bucket_name}/{s3_prefix}`")
    try:
        with st.spinner("Loading LogBERT alerts from S3…"):
            df_full = load_alerts_from_s3(bucket_name, s3_prefix, aws_region_default)
    except Exception as e:
        st.error("Failed to load alerts from S3.")
        st.code(str(e))
        st.stop()

    if df_full.empty:
        st.warning("No anomaly alert JSON files found in S3 yet.")
        st.stop()
    st.success(f"✅ Loaded **{len(df_full):,}** LogBERT alert entries from S3")

elif data_mode == "Upload file":
    if uploaded_file is not None:
        with st.spinner("Analysing logs…"):
            df_full = load_and_score(uploaded_file.read(), uploaded_file.name)
        st.success(f"✅ Loaded **{len(df_full):,}** log entries from **{uploaded_file.name}**")
    else:
        st.info("👈 Upload a CSV or .log file from the sidebar to get started.")
        st.stop()
else:
    with st.spinner("Loading project dataset…"):
        df_full = load_default_dataset()
    if df_full is None:
        st.error("full_dataset_final.csv not found. Place it in the same folder as dashboard.py.")
        st.stop()
    st.success(f"✅ Loaded project dataset — **{len(df_full):,}** entries")

# ── Apply filters ──────────────────────────────────────────
df = df_full[
    (df_full["threat_score"] >= score_threshold) &
    (df_full["severity"].isin(severity_filter))
].copy()

if df.empty:
    st.warning("No logs match the selected filters.")
    st.stop()

# ─────────────────────────────────────────────────────────────
# KPI CARDS  — old dashboard layout
# ─────────────────────────────────────────────────────────────
st.markdown("---")
c1, c2, c3, c4, c5 = st.columns(5)
total = len(df)
n_critical = (df["severity"] == "CRITICAL").sum()
n_high = (df["severity"] == "HIGH").sum()
n_medium = (df["severity"] == "MEDIUM").sum()
n_anomaly = (df["threat_score"] > 0).sum()
anomaly_pct = round(n_anomaly / total * 100, 1) if total else 0

c1.metric("Total Logs", f"{total:,}")
c2.metric("🔴 Critical", f"{n_critical:,}")
c3.metric("🟠 High", f"{n_high:,}")
c4.metric("🟡 Medium", f"{n_medium:,}")
c5.metric("⚠️ Anomaly Rate", f"{anomaly_pct}%")

# ─────────────────────────────────────────────────────────────
# CHARTS ROW 1  — old dashboard graphs
# ─────────────────────────────────────────────────────────────
st.markdown("---")
col_a, col_b = st.columns([1, 2])
with col_a:
    st.plotly_chart(chart_severity_donut(df), use_container_width=True)
with col_b:
    st.plotly_chart(chart_threat_score_hist(df), use_container_width=True)

# ─────────────────────────────────────────────────────────────
# CHARTS ROW 2  — old dashboard graphs
# ─────────────────────────────────────────────────────────────
col_c, col_d = st.columns(2)
with col_c:
    st.plotly_chart(chart_score_over_time(df), use_container_width=True)
with col_d:
    fig_src = chart_source_breakdown(df)
    if fig_src:
        st.plotly_chart(fig_src, use_container_width=True)
    else:
        st.info("No source column found in this dataset.")

# ─────────────────────────────────────────────────────────────
# TOP THREATS CHART  — old dashboard graph
# ─────────────────────────────────────────────────────────────
st.plotly_chart(chart_top_threats(df, n=10), use_container_width=True)

# ─────────────────────────────────────────────────────────────
# ALERTS SECTION  — old dashboard thresholds/tabs
# ─────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("🚨 Active Security Alerts")

alerts_gt14 = df[df["threat_score"] > 14].sort_values("threat_score", ascending=False)
alerts_gt9 = df[(df["threat_score"] > 9) & (df["threat_score"] <= 14)].sort_values("threat_score", ascending=False)

# S3 email threshold note only appears for S3 data; it does not change the old visual layout.
if data_mode == "Amazon S3 LogBERT alerts":
    email_alerts = int((df["threat_score"] > EMAIL_THRESHOLD).sum())
    st.caption(f"S3/Lambda email threshold reference: score > {EMAIL_THRESHOLD} — {email_alerts} filtered alerts currently above this level.")

tab1, tab2 = st.tabs([
    f"🔴 Critical / Extreme Score > 14  ({len(alerts_gt14)} alerts)",
    f"🟠 Medium-High Score > 9 to 14  ({len(alerts_gt9)} alerts)",
])


def render_alert_table(alerts_df, tab_label):
    if alerts_df.empty:
        st.success("✅ No alerts at this threshold.")
        return

    display_cols = [c for c in [
        "timestamp", "log_message", "threat_score", "severity", "source",
        "window_id", "lines", "alert_type", "reason", "s3_key"
    ] if c in alerts_df.columns]

    table_df = alerts_df[display_cols].copy()
    if "severity" in display_cols:
        styled = table_df.style.map(
            lambda v: f"color: {SEVERITY_COLORS.get(v, '#000')}; font-weight: bold"
            if v in SEVERITY_COLORS else "",
            subset=["severity"]
        )
        st.dataframe(styled, use_container_width=True, height=300)
    else:
        st.dataframe(table_df, use_container_width=True, height=300)

    if alert_enabled and sns_topic_arn:
        if st.button(f"📤 Send SNS Alerts for all {tab_label}", key=f"sns_{tab_label}"):
            sent, failed = 0, 0
            progress = st.progress(0, text="Sending alerts…")
            for i, (_, row) in enumerate(alerts_df.iterrows()):
                result = send_sns_alert(
                    subject=f"[{row['severity']}] Threat Score {row['threat_score']} — Log Alert",
                    message=build_alert_message(row),
                    topic_arn=sns_topic_arn,
                    region=sns_region,
                    aws_key=aws_key,
                    aws_secret=aws_secret,
                )
                if result["success"]:
                    sent += 1
                else:
                    failed += 1
                progress.progress((i + 1) / len(alerts_df), text=f"Sent {i+1}/{len(alerts_df)}")
            progress.empty()
            if failed == 0:
                st.success(f"✅ Sent {sent} SNS alerts successfully.")
            else:
                st.warning(f"Sent: {sent} ✅  |  Failed: {failed} ❌")
    elif alert_enabled and not sns_topic_arn:
        st.warning("Enter your SNS Topic ARN in the sidebar to send alerts.")


with tab1:
    render_alert_table(alerts_gt14, "gt14")
with tab2:
    render_alert_table(alerts_gt9, "gt9")

# ─────────────────────────────────────────────────────────────
# FULL LOG TABLE  — old dashboard section, with S3 columns added when present
# ─────────────────────────────────────────────────────────────
st.markdown("---")
with st.expander("📋 Full Log Table (filtered)", expanded=False):
    display_cols = [c for c in [
        "timestamp", "log_message", "threat_score", "severity", "source", "label",
        "window_id", "lines", "alert_type", "reason", "recommendation_required", "s3_key"
    ] if c in df.columns]
    st.dataframe(df[display_cols], use_container_width=True, height=400)

    csv_bytes = df[display_cols].to_csv(index=False).encode()
    st.download_button(
        "⬇️ Download Scored Logs as CSV",
        data=csv_bytes,
        file_name=f"scored_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv"
    )

# ─────────────────────────────────────────────────────────────
# SINGLE LOG ANALYSER  — kept from old dashboard
# ─────────────────────────────────────────────────────────────
st.markdown("---")
st.subheader("🔍 Analyse a Single Log Entry")
manual_log = st.text_area(
    "Paste a log line here:",
    placeholder="e.g.  Failed password for root from 192.168.1.9 port 55221 ssh2",
    height=80
)
if st.button("Analyse Log"):
    if manual_log.strip():
        cleaned = normalise_log(manual_log)
        score = compute_threat_score(cleaned)
        sev = severity_label(score)
        col1, col2, col3 = st.columns(3)
        col1.metric("Threat Score", f"{score} / 100")
        col2.metric("Severity", sev)
        col3.metric("Anomaly", "Yes" if score > 0 else "No")
        st.markdown(f"**Cleaned log:** `{cleaned}`")

        if alert_enabled and sns_topic_arn and score > 9:
            row = pd.Series({
                "log_message": manual_log,
                "threat_score": score,
                "severity": sev,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source": "manual_entry"
            })
            if st.button("📤 Send SNS Alert for this log", key="sns_manual"):
                result = send_sns_alert(
                    subject=f"[{sev}] Manual Log Alert — Score {score}",
                    message=build_alert_message(row),
                    topic_arn=sns_topic_arn,
                    region=sns_region,
                    aws_key=aws_key,
                    aws_secret=aws_secret,
                )
                if result["success"]:
                    st.success(f"✅ Alert sent! {result['message']}")
                else:
                    st.error(f"❌ Failed: {result['message']}")
    else:
        st.warning("Please paste a log line above.")

# ─────────────────────────────────────────────────────────────
# FOOTER
# ─────────────────────────────────────────────────────────────
st.markdown("---")
st.caption("COIT20265 — NLP-Based Log Anomaly Detection · CQUniversity Australia")
st.caption(f"Dashboard last refreshed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC")
