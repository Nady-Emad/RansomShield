import time
import os

DIR = r"C:\monitor"
os.makedirs(DIR, exist_ok=True)

while True:
    with open(os.path.join(DIR, "file.txt"), "a") as f:
        f.write("DATA\n" * 50)
    time.sleep(0.02)