import os
import time

DIR = r"C:\monitor"
os.makedirs(DIR, exist_ok=True)

i = 0
while True:
    src = os.path.join(DIR, f"f{i}.txt")
    dst = src + ".locked"

    with open(src, "w") as f:
        f.write("ENCRYPTED\n")

    os.rename(src, dst)
    i += 1
    time.sleep(0.05)