import json
from datetime import datetime, timezone

import boto3
import pandas as pd
import plotly.express as px
import streamlit as st


# --------------------------------------------------
# Page config
# --------------------------------------------------
st.set_page_config(
    page_title="LogBERT Anomaly Dashboard",
    page_icon="🔐",
    layout="wide"
)


# --------------------------------------------------
# S3 settings
# --------------------------------------------------
BUCKET_NAME = "logbert-dashboard-alerts-914115115831"
S3_PREFIX = "logbert-alerts/"


# --------------------------------------------------
# Helper: read secret safely
# --------------------------------------------------
def get_secret_value(key: str, default: str = ""):
    try:
        return st.secrets[key]
    except Exception:
        return default


# --------------------------------------------------
# Load LogBERT JSON alerts from S3
# --------------------------------------------------
@st.cache_data(ttl=60)
def load_alerts_from_s3() -> pd.DataFrame:
    aws_access_key = get_secret_value("AWS_ACCESS_KEY_ID")
    aws_secret_key = get_secret_value("AWS_SECRET_ACCESS_KEY")
    aws_region = get_secret_value("AWS_DEFAULT_REGION", "ap-southeast-2")

    if not aws_access_key or not aws_secret_key:
        raise ValueError(
            "AWS credentials are missing. Add AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, and AWS_DEFAULT_REGION in Streamlit Secrets."
        )

    s3 = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )

    alerts = []
    continuation_token = None

    while True:
        list_kwargs = {
            "Bucket": BUCKET_NAME,
            "Prefix": S3_PREFIX
        }

        if continuation_token:
            list_kwargs["ContinuationToken"] = continuation_token

        response = s3.list_objects_v2(**list_kwargs)

        for obj in response.get("Contents", []):
            key = obj["Key"]

            if not key.endswith(".json"):
                continue

            try:
                file_obj = s3.get_object(Bucket=BUCKET_NAME, Key=key)
                content = file_obj["Body"].read().decode("utf-8")
                alert = json.loads(content)

                # Add S3 metadata
                alert["s3_key"] = key
                alert["last_modified"] = obj["LastModified"]

                alerts.append(alert)

            except Exception as e:
                # Skip broken JSON/object but keep app running
                print(f"Skipping file {key}: {e}")

        if response.get("IsTruncated"):
            continuation_token = response.get("NextContinuationToken")
        else:
            break

    if not alerts:
        return pd.DataFrame()

    df = pd.DataFrame(alerts)

    # --------------------------------------------------
    # Make the dashboard compatible with your S3 JSON format
    # --------------------------------------------------
    if "score" in df.columns:
        df["threat_score"] = pd.to_numeric(df["score"], errors="coerce").fillna(0)
    else:
        df["threat_score"] = 0

    if "alert_level" in df.columns:
        df["severity"] = df["alert_level"].fillna("UNKNOWN")
    else:
        df["severity"] = "UNKNOWN"

    if "last_modified" in df.columns:
        df["timestamp"] = pd.to_datetime(df["last_modified"], errors="coerce")
    else:
        df["timestamp"] = pd.Timestamp.now(tz="UTC")

    if "sample_logs" in df.columns:
        df["log_message"] = df["sample_logs"].apply(
            lambda logs: " | ".join(logs) if isinstance(logs, list) else str(logs)
        )
    else:
        df["log_message"] = ""

    # Ensure optional fields exist
    for col in [
        "source",
        "window_id",
        "lines",
        "start_line",
        "end_line",
        "alert_type",
        "reason",
        "recommendation_required",
        "s3_key"
    ]:
        if col not in df.columns:
            df[col] = ""

    return df.sort_values("timestamp", ascending=False).reset_index(drop=True)


# --------------------------------------------------
# Header
# --------------------------------------------------
st.title("🔐 LogBERT Cloud Anomaly Detection Dashboard")
st.caption(
    "This dashboard reads LogBERT anomaly JSON alerts from Amazon S3. "
    "Email alerts and OpenAI recommendations are handled separately by AWS Lambda."
)


# --------------------------------------------------
# Refresh button
# --------------------------------------------------
col_refresh, col_info = st.columns([1, 4])

with col_refresh:
    if st.button("🔄 Refresh data"):
        st.cache_data.clear()
        st.rerun()

with col_info:
    st.info(
        f"Reading from: s3://{BUCKET_NAME}/{S3_PREFIX}"
    )


# --------------------------------------------------
# Load data
# --------------------------------------------------
try:
    df = load_alerts_from_s3()
except Exception as e:
    st.error("Failed to load alerts from S3.")
    st.code(str(e))
    st.stop()

if df.empty:
    st.warning("No anomaly alerts found in S3 yet.")
    st.stop()


# --------------------------------------------------
# Sidebar filters
# --------------------------------------------------
st.sidebar.header("Filters")

max_score = float(max(df["threat_score"].max(), 20))

min_score = st.sidebar.slider(
    "Minimum anomaly score",
    min_value=0.0,
    max_value=max_score,
    value=0.0,
    step=0.1
)

severity_options = sorted(df["severity"].dropna().unique().tolist())

selected_severity = st.sidebar.multiselect(
    "Alert level",
    severity_options,
    default=severity_options
)

alert_type_options = sorted(df["alert_type"].dropna().unique().tolist())

selected_alert_types = st.sidebar.multiselect(
    "Alert type",
    alert_type_options,
    default=alert_type_options
)

only_email_threshold = st.sidebar.checkbox(
    "Show only alerts above email threshold > 11.8",
    value=False
)


# --------------------------------------------------
# Apply filters
# --------------------------------------------------
df_filtered = df[
    (df["threat_score"] >= min_score)
    & (df["severity"].isin(selected_severity))
    & (df["alert_type"].isin(selected_alert_types))
].copy()

if only_email_threshold:
    df_filtered = df_filtered[df_filtered["threat_score"] > 11.8].copy()


# --------------------------------------------------
# KPI cards
# --------------------------------------------------
st.markdown("---")

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Total Alerts", len(df_filtered))

if df_filtered.empty:
    c2.metric("Highest Score", "N/A")
    c3.metric("Average Score", "N/A")
    c4.metric("Email-Level Alerts", "0")
else:
    c2.metric("Highest Score", round(df_filtered["threat_score"].max(), 4))
    c3.metric("Average Score", round(df_filtered["threat_score"].mean(), 4))
    c4.metric("Email-Level Alerts", int((df_filtered["threat_score"] > 11.8).sum()))

c5.metric("Email Threshold", "> 11.8")


# --------------------------------------------------
# Stop if filters remove all rows
# --------------------------------------------------
if df_filtered.empty:
    st.warning("No alerts match the selected filters.")
    st.stop()


# --------------------------------------------------
# Charts
# --------------------------------------------------
st.markdown("---")

col1, col2 = st.columns(2)

with col1:
    severity_counts = df_filtered["severity"].value_counts().reset_index()
    severity_counts.columns = ["severity", "count"]

    fig_severity = px.pie(
        severity_counts,
        names="severity",
        values="count",
        title="Alert Level Distribution"
    )

    st.plotly_chart(fig_severity, use_container_width=True)

with col2:
    fig_hist = px.histogram(
        df_filtered,
        x="threat_score",
        nbins=20,
        title="Anomaly Score Distribution",
        labels={"threat_score": "Anomaly Score"}
    )

    fig_hist.add_vline(
        x=11.8,
        line_dash="dash",
        annotation_text="Email threshold > 11.8",
        annotation_position="top right"
    )

    st.plotly_chart(fig_hist, use_container_width=True)


st.markdown("---")

fig_time = px.scatter(
    df_filtered,
    x="timestamp",
    y="threat_score",
    color="severity",
    hover_data=["alert_type", "reason", "lines"],
    title="Anomaly Score Over Time",
    labels={
        "timestamp": "Time",
        "threat_score": "Anomaly Score"
    }
)

fig_time.add_hline(
    y=11.8,
    line_dash="dash",
    annotation_text="Email threshold > 11.8",
    annotation_position="top right"
)

st.plotly_chart(fig_time, use_container_width=True)


# --------------------------------------------------
# Alert type chart
# --------------------------------------------------
st.markdown("---")

alert_type_counts = df_filtered["alert_type"].value_counts().reset_index()
alert_type_counts.columns = ["alert_type", "count"]

fig_type = px.bar(
    alert_type_counts,
    x="alert_type",
    y="count",
    title="Alert Count by Type",
    labels={
        "alert_type": "Alert Type",
        "count": "Number of Alerts"
    }
)

st.plotly_chart(fig_type, use_container_width=True)


# --------------------------------------------------
# Alert table
# --------------------------------------------------
st.markdown("---")
st.subheader("Detected LogBERT Alerts")

display_cols = [
    "timestamp",
    "source",
    "window_id",
    "lines",
    "threat_score",
    "severity",
    "alert_type",
    "reason",
    "recommendation_required",
    "log_message",
    "s3_key"
]

available_cols = [col for col in display_cols if col in df_filtered.columns]

st.dataframe(
    df_filtered[available_cols],
    use_container_width=True,
    height=450
)


# --------------------------------------------------
# Detailed alert viewer
# --------------------------------------------------
st.markdown("---")
st.subheader("Alert Details")

selected_index = st.selectbox(
    "Select an alert row to inspect",
    options=df_filtered.index.tolist(),
    format_func=lambda i: (
        f"Window {df_filtered.loc[i, 'window_id']} | "
        f"Score {df_filtered.loc[i, 'threat_score']} | "
        f"{df_filtered.loc[i, 'alert_type']}"
    )
)

selected_alert = df_filtered.loc[selected_index]

detail_col1, detail_col2 = st.columns(2)

with detail_col1:
    st.markdown("#### Alert Summary")
    st.write(f"**Score:** {selected_alert.get('threat_score')}")
    st.write(f"**Severity:** {selected_alert.get('severity')}")
    st.write(f"**Alert Type:** {selected_alert.get('alert_type')}")
    st.write(f"**Lines:** {selected_alert.get('lines')}")
    st.write(f"**Reason:** {selected_alert.get('reason')}")

with detail_col2:
    st.markdown("#### Sample Logs")
    sample_logs = selected_alert.get("sample_logs", [])

    if isinstance(sample_logs, list):
        for log in sample_logs:
            st.code(log)
    else:
        st.code(str(sample_logs))


# --------------------------------------------------
# Download filtered alerts
# --------------------------------------------------
st.markdown("---")

csv = df_filtered[available_cols].to_csv(index=False).encode("utf-8")

st.download_button(
    label="⬇️ Download filtered alerts as CSV",
    data=csv,
    file_name=f"logbert_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    mime="text/csv"
)


# --------------------------------------------------
# Footer
# --------------------------------------------------
st.caption(
    f"Last refreshed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
)