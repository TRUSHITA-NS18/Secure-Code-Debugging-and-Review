import sys, shutil, importlib.util
print("Python:", sys.version)
print("Free disk:", round(shutil.disk_usage(".").free / (1024**3), 2), "GiB")
for name in ["streamlit","google.genai","chromadb","fitz","dotenv","numpy","pandas"]:
    try: ok = importlib.util.find_spec(name) is not None
    except ModuleNotFoundError: ok = False
    print(f"{name}: {'available' if ok else 'not installed'}")
