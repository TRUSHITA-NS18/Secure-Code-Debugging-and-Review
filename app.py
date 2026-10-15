import os
import streamlit as st
import pandas as pd
from dotenv import load_dotenv
from rag_engine import analyze_code, explain_code, retrieve_guidelines, analyze_logs, make_report, save_review, load_reviews

load_dotenv()
st.set_page_config(page_title="Secure Code Review Assistant", page_icon="🛡️", layout="wide")
st.title("🛡️ Secure Code Debugging & Review Assistant")
st.caption("Local-first prototype • Human approval required • Not a certified MISRA/static-analysis tool")

with st.sidebar:
    st.subheader("Security & privacy")
    st.info("Default analysis is local. No source code is sent externally unless you explicitly enable Gemini.")
    use_ai = st.checkbox("Enable Gemini explanation (external API)", value=False)
    if use_ai:
        st.warning("Selected source/log context will be sent to Google Gemini. Use only with approved, non-confidential code.")
        if not os.getenv("GOOGLE_API_KEY"):
            st.error("GOOGLE_API_KEY is missing. Add it to .env to enable Gemini.")
    project = st.text_input("Project / module", "Demo ECU Module")
    reviewer = st.text_input("Reviewer", "Local Reviewer")

review_tab, guide_tab, history_tab, about_tab = st.tabs(["🔍 Code review", "📚 Coding guidance", "🧾 History", "ℹ️ About"])
with review_tab:
    left, right = st.columns(2)
    with left:
        mode = st.radio("Input", ["Paste code", "Upload file"], horizontal=True)
        filename, code = "pasted_code.c", ""
        if mode == "Paste code":
            code = st.text_area("Source code", height=330, placeholder="Paste C/C++/Python code here…")
        else:
            up = st.file_uploader("Upload source/log", type=["c","h","cpp","hpp","py","txt","log","md"])
            if up:
                filename = os.path.basename(up.name)
                code = up.getvalue().decode("utf-8", errors="replace")
        st.caption("Do not include passwords, production secrets, or data you are not authorized to share.")
        run = st.button("Run local review", type="primary", use_container_width=True)
    with right:
        st.subheader("Findings")
        if run:
            if not code.strip():
                st.warning("Paste or upload code first.")
            else:
                findings = analyze_code(code, filename)
                guidance = retrieve_guidelines(code, 4)
                review = {"project": project, "reviewer": reviewer, "filename": filename, "code": code,
                          "findings": findings, "guidance": guidance}
                if use_ai and os.getenv("GOOGLE_API_KEY"):
                    try:
                        from rag_engine import gemini_explanation
                        review["ai_explanation"] = gemini_explanation(code, findings, guidance)
                    except Exception as e:
                        review["ai_error"] = str(e)
                st.session_state["review"] = review
                save_review(review)
        review = st.session_state.get("review")
        if review:
            findings = review["findings"]
            a,b,c = st.columns(3)
            a.metric("Findings", len(findings))
            b.metric("High severity", sum(f["severity"] == "High" for f in findings))
            c.metric("Open", sum(f.get("status","Open") == "Open" for f in findings))
            if findings:
                st.dataframe(pd.DataFrame(findings)[["severity","rule_id","title","line","evidence","recommendation","status"]],
                             use_container_width=True, hide_index=True)
                for i, f in enumerate(findings):
                    with st.expander(f'{f["severity"]} · {f["rule_id"]} · {f["title"]}'):
                        st.write("**Evidence**"); st.code(f["evidence"])
                        st.write("**Why it matters:** " + f["rationale"])
                        st.write("**Suggested action:** " + f["recommendation"])
                        f["status"] = st.selectbox("Reviewer disposition", ["Open","Accepted","False positive","Fixed","Needs investigation"],
                                                   index=["Open","Accepted","False positive","Fixed","Needs investigation"].index(f.get("status","Open")),
                                                   key=f"status_{i}")
                if st.button("Save reviewer dispositions"):
                    save_review(review); st.success("Saved locally.")
            else:
                st.success("No prototype rules triggered. This does not prove the code is safe.")
            st.subheader("Code summary")
            st.write(explain_code(code))
            if review.get("guidance"):
                st.subheader("Related local guidance")
                for g in review["guidance"]:
                    st.markdown(f'**{g["title"]}** — {g["excerpt"]}')
                    st.caption("Source: " + g["source"])
            if review.get("ai_explanation"):
                st.subheader("Optional Gemini explanation"); st.write(review["ai_explanation"])
            if review.get("ai_error"):
                st.warning("Gemini unavailable: " + review["ai_error"])
            st.download_button("Download Markdown report", make_report(review), "secure_code_review_report.md", "text/markdown")
        else:
            st.info("Run a review to see structured findings and remediation suggestions.")

    st.divider()
    st.subheader("Compiler / static-analysis log triage")
    logs = st.text_area("Paste warnings or runtime logs", height=100)
    if st.button("Summarize log locally"):
        st.write(analyze_logs(logs) if logs.strip() else "Paste a log first.")

with guide_tab:
    st.subheader("Local coding guidance")
    st.write("Add approved .md or .txt rules to data/guidelines/. Default retrieval is lightweight and local.")
    query = st.text_input("Search guidance", placeholder="bounds checking, secrets, command execution")
    if query:
        for g in retrieve_guidelines(query, 8):
            st.markdown("**" + g["title"] + "**")
            st.write(g["excerpt"]); st.caption(g["source"])
    from rag_engine import list_guideline_files
    st.write("Guideline files:")
    for p in list_guideline_files(): st.code(p)

with history_tab:
    history = load_reviews()
    if history:
        frame = pd.DataFrame([{"timestamp":x.get("timestamp",""),"project":x.get("project",""),
                               "file":x.get("filename",""),"reviewer":x.get("reviewer",""),
                               "findings":len(x.get("findings",[]))} for x in history])
        st.dataframe(frame, use_container_width=True, hide_index=True)
        st.download_button("Export history CSV", frame.to_csv(index=False), "review_history.csv", "text/csv")
    else:
        st.info("No reviews saved yet.")

with about_tab:
    st.markdown("""
### Prototype capabilities
- Candidate security and defect checks with line evidence and suggested actions.
- Code structure summary, compiler-log triage, local guideline retrieval.
- Structured findings, reviewer disposition, local history, Markdown report export.

### Limitations and controls
This is not a certified MISRA checker, compiler, static analyzer, or replacement for qualified review.
No automatic edits, merges, or release approval. Findings can be false positives or miss defects.
Gemini is OFF by default and transmits selected text externally when enabled.
Enterprise authentication, repository permissions, encryption-at-rest, and CI/CD integration are future work.
""")
