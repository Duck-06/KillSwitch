import subprocess
import sys
import os
from pathlib import Path

# Paths to your scripts
PREDICT_SCRIPT = "predict_offline.py"
APP_SCRIPT = "app.py"

def run_predict():
    print("Running offline prediction script...")
    subprocess.run([sys.executable, PREDICT_SCRIPT], check=True)

def run_streamlit_app():
    print("Launching Streamlit dashboard (app.py)...")
    subprocess.run(["streamlit", "run", APP_SCRIPT], check=True)

if __name__ == "__main__":
    # Change working directory to script's location
    os.chdir(Path(__file__).parent)

    run_predict()
    run_streamlit_app()
