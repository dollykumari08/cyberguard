import random
import datetime
import pandas as pd
import plotly.express as px
import streamlit as st
from detect import analyze_message, analyze_login, analyze_media, _package
st.set_page_config(page_title="CyberGuard", layout="wide")
LEVELS = ["Safe", "Low", "Medium", "High", "Critical"]
COLORS = {"Safe": "#2ecc71", "Low": "#f1c40f", "Medium": "#e67e22",
          "High": "#e74c3c", "Critical": "#8e0000"}
USERS = ["Priyanka", "Sam", "Doll", "Aalia", "John"]


def simulate(n=60):
    random.seed(7)
    now = datetime.datetime.now()
    out = []
    for _ in range(n):
        u = random.choice(USERS)
        k = random.choice(["phish", "imp", "login", "safe", "safe_login", "mild", "mild", "mild", "mild","deepfake","deepfake","deepfake"])
        if k == "phish":
            e = analyze_message("security@sbi-alerts.com", "SBI Alerts",
                                "URGENT: Your account will be suspended. Verify your password now",
                                url=random.choice(["http://sbi-verify-login.xyz/login",
                                                   "http://paypa1-secure.top/auth",
                                                   "http://192.168.4.7/bank/update"]), target=u)
        elif k == "imp":
            e = analyze_message("director.bput@gmail.com", "Director BPUT",
                                "CEO here. I need gift cards urgently, keep this confidential. Reply fast",
                                target=u)
        elif k == "login":
            e = analyze_login(u, random.choice([1, 2, 3]), random.choice(["RU", "CN", "NG"]),
                              True, random.randint(5, 15))
        elif k == "safe":
            e = analyze_message("hr@bput.ac.in", "HR",
                                "Hi team, the meeting is moved to 3 PM tomorrow in room 204.", target=u)
        elif k == "mild":
            body = "Hi team, the meeting is moved to 3 PM tomorrow in room 204."
            options = [
                lambda: analyze_message("hr@bput.ac.com", "HR Office", body, target=u),
                lambda: analyze_message("hr@bput.ac.in", "HR", body, url="http://shop-deals.com/offer", target=u),
                lambda: analyze_message("hr@bput.ac.in", "HR", body, url="https://paypa1-help.com/login", target=u),
                lambda: analyze_message("hr@bput.ac.in", "HR", body, url="http://secure-update.net/verify", target=u),
                lambda: analyze_login(u, 22, "IN", False, 2),
                lambda: analyze_login(u, 11, "IN", True, 1),
                lambda: analyze_login(u, 14, "US", False, 0),
            ]
            e = random.choice(options)()
        elif k == "deepfake":
            e = _package("Image", "Deepfake", random.choice([35, 55, 72, 90]),
                         random.sample(["No camera metadata (EXIF) found",
                                        "Unnaturally smooth texture",
                                        "Square 1024x1024 resolution typical of AI generators",
                                        "Inconsistent compression across regions"], 2), u)    
        else:
            e = analyze_login(u, random.randint(9, 18), "IN", False, 0)
        e["timestamp"] = now - datetime.timedelta(minutes=random.randint(0, 720))
        if e["status"] == "Open":
            e["status"] = random.choice(["Open", "Open", "Investigating", "Resolved"])
        out.append(e)
    return out


if "events" not in st.session_state:
    st.session_state.events = simulate()

st.title("🛡️ CyberGuard: AI Cyber Defence Command Center")
tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🔍 Analyze Live", "📈 Model Performance"])
# ---------------- DASHBOARD ----------------
with tab1:
    df = pd.DataFrame(st.session_state.events)
    df["actions_txt"] = df["actions"].apply(lambda a: ", ".join(a))
    threats = df[df.level != "Safe"]

    c = st.columns(6)
    c[0].metric("Events analysed", len(df))
    c[1].metric("Threats detected", len(threats))
    c[2].metric("Phishing", int((df.category == "Phishing").sum()))
    c[3].metric("Impersonation", int((df.category == "Impersonation").sum()))
    c[4].metric("Account takeover", int((df.category == "Account Takeover").sum()))
    c[5].metric("Suspected deepfakes", int((df.category == "Deepfake").sum()))

    l, r = st.columns(2)
    with l:
        cat = threats.category.value_counts().reset_index()
        cat.columns = ["category", "count"]
        st.plotly_chart(px.pie(cat, names="category", values="count", title="Threat categories"),
                        use_container_width=True)
    with r:
        lv = df.level.value_counts().reindex(LEVELS, fill_value=0).reset_index()
        lv.columns = ["level", "count"]
        st.plotly_chart(px.bar(lv, x="level", y="count", color="level",
                               color_discrete_map=COLORS, title="Risk levels"),
                        use_container_width=True)

    l, r = st.columns(2)
    with l:
        tl = threats.copy()
        tl["hour"] = tl.timestamp.dt.floor("h")
        tl = tl.groupby(["hour", "category"]).size().reset_index(name="count")
        st.plotly_chart(px.line(tl, x="hour", y="count", color="category", markers=True,
                                title="Attack timeline"), use_container_width=True)
    with r:
        tg = threats.target.value_counts().reset_index()
        tg.columns = ["user", "attacks"]
        st.plotly_chart(px.bar(tg, x="user", y="attacks", title="Most targeted users"),
                        use_container_width=True)

    st.subheader("Incidents")
    f1, f2 = st.columns(2)
    lvl_f = f1.multiselect("Risk level", LEVELS[1:], default=LEVELS[1:])
    st_f = f2.multiselect("Status", sorted(df.status.unique()), default=["Open", "Investigating"])
    view = threats[threats.level.isin(lvl_f) & threats.status.isin(st_f)] \
        .sort_values("score", ascending=False)
    st.dataframe(view[["timestamp", "target", "category", "level", "score", "status",
                       "explanation", "actions_txt", "mitre"]], height=350)

# ---------------- LIVE ANALYSIS ----------------
def show(res):
    box = {"Safe": st.success, "Low": st.info, "Medium": st.warning}.get(res["level"], st.error)
    box(f"**{res['level']} risk** | {res['category']} | score {res['score']}/100")
    st.write("**Explanation:**", res["explanation"])
    st.write("**Recommended actions:**")
    for a in res["actions"]:
        st.write("•", a)
    st.caption(f"MITRE ATT&CK: {res['mitre']}")


with tab2:
    mode = st.radio("Scenario", ["Email / SMS", "Login event", "Image (deepfake)"], horizontal=True)
    if mode == "Email / SMS":
        sender = st.text_input("Sender email", "security@sbi-alerts.com")
        name = st.text_input("Display name", "SBI Alerts")
        body = st.text_area("Message", "URGENT: Your account will be suspended. Verify your password now")
        url = st.text_input("URL in message (optional)", "http://sbi-verify-login.xyz/login")
        if st.button("Analyze"):
            res = analyze_message(sender, name, body, url=url, target="live-user")
            res["timestamp"] = datetime.datetime.now()
            st.session_state.events.append(res)
            show(res)
    elif mode == "Login event":
        user = st.selectbox("User", USERS)
        hour = st.slider("Login hour", 0, 23, 2)
        country = st.selectbox("Country", ["IN", "RU", "CN", "NG", "BR", "US"], index=1)
        new_dev = st.checkbox("New device", True)
        failed = st.slider("Failed attempts", 0, 20, 12)
        if st.button("Analyze login"):
            res = analyze_login(user, hour, country, new_dev, failed)
            res["timestamp"] = datetime.datetime.now()
            st.session_state.events.append(res)
            show(res)
    else:
        from PIL import Image
        up = st.file_uploader("Upload an image", type=["jpg", "jpeg", "png", "webp"])
        if up is not None:
            img = Image.open(up)
            st.image(img, width=300)
            if st.button("Analyze image"):
                res = analyze_media(img, target="live-user")
                res["timestamp"] = datetime.datetime.now()
                st.session_state.events.append(res)
                show(res)
import json

with tab3:
    try:
        M = json.load(open("data/metrics.json"))
    except Exception:
        M = None
        st.error("metrics.json not found. Run evaluate.py first.")
    if M:
        blocks = [("phishing", "Phishing text model (real Kaggle data)", ["Legit", "Phishing"]),
                  ("login", "Login anomaly model (simulated logs)", ["Normal", "Attack"])]
        for key, title, lab in blocks:
            m = M[key]
            st.subheader(title)
            if key == "phishing":
                st.caption("Dataset: 'Phishing and Legit Emails' by Prabhat Amgain (Kaggle, MIT license), 38,164 emails, 75/25 train-test split.")
            else:
                st.caption("Dataset: simulated login logs (1,000 normal + 60 attack events).")
            c = st.columns(5)
            c[0].metric("Accuracy", f"{m['accuracy']:.1%}")
            c[1].metric("Precision", f"{m['precision']:.2f}")
            c[2].metric("Recall", f"{m['recall']:.2f}")
            c[3].metric("F1-score", f"{m['f1']:.2f}")
            c[4].metric("Test samples", m["n_test"])
            fig = px.imshow(m["confusion"], text_auto=True, color_continuous_scale="Blues",
                            x=["Predicted " + lab[0], "Predicted " + lab[1]],
                            y=["Actual " + lab[0], "Actual " + lab[1]],
                            title="Confusion matrix")
            st.plotly_chart(fig, use_container_width=True)