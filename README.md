# Secure Code Debugging and Review Assistant

Storage-conscious, local-first Streamlit prototype for Case Study 4.

## Included
- Local heuristic checks for hard-coded secrets, command execution, unsafe C string functions, array indexing, pointer-sensitive operations, resource acquisition, unsafe evaluation/deserialization, and TODO/FIXME markers.
- Code structure summary and compiler/build log triage.
- Retrieval from local coding guidance files.
- Structured findings with severity, rule ID, line, evidence, rationale, suggested action, and reviewer disposition.
- Local JSON review history and Markdown/CSV export.
- Optional Gemini explanation, disabled by default.

## Privacy
Default mode makes no network requests and does not send code externally. Optional Gemini mode sends selected source and findings to the Google Gemini API. Only enable it for code approved for external processing. Never commit your API key.

This student prototype is not enterprise authentication, a certified MISRA checker, a compiler/static analyzer, or a substitute for a qualified reviewer. It does not automatically edit code, merge changes, or approve releases.

## Run on Windows (PowerShell)
Install Python 3.11 or 3.12 (64-bit), extract the ZIP, open the folder in VS Code, then:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, use Command Prompt:
```bat
.venv\Scripts\activate.bat
pip install -r requirements.txt
streamlit run app.py
```
Open the local URL Streamlit prints, normally http://localhost:8501.

## Storage notes
No local LLM weights are downloaded. This keeps the prototype far smaller than a local model setup. ChromaDB and its dependencies may still take disk space. The default retrieval is lightweight local keyword retrieval, so the demo can run without building a vector index. The requested packages are all declared in requirements.txt for the expected stack.

If disk is critically low, first run `python scripts/check_environment.py` to inspect free disk. A minimal baseline environment can use `pip install streamlit python-dotenv pandas`; install the full requirements file when you have enough space to satisfy the requested stack.

## Optional Gemini
Copy `.env.example` to `.env`, add an approved key, and manually enable Gemini in the sidebar. Never commit `.env`. Use non-confidential sample code unless your organization explicitly approves external processing.

## Demo
1. Start the app.
2. Paste `data/sample_code/demo_vulnerable.c`.
3. Run local review and inspect evidence.
4. Set dispositions and save.
5. Download the Markdown report.
6. Search local guidance or paste a compiler warning into log triage.
7. Run `python run_evaluation.py` for a smoke test.

## Next phases
1. Add authentication and repository/path-level permissions.
2. Ingest internal PDF rules with PyMuPDF.
3. Add persistent local ChromaDB indexing and metadata filters.
4. Add an approved local model only if RAM/disk allow.
5. Integrate tools such as clang-tidy/cppcheck and preserve tool evidence.
6. Add audit logging, test fixtures, reviewer workflow, and measured finding precision.
