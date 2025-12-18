import time

CANARY = r"C:\monitor\canary1.txt"

while True:
    with open(CANARY, "a") as f:
        f.write("TAMPERED\n")
    time.sleep(1)