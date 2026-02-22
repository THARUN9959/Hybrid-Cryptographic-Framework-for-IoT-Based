import cv2
import os
import time
import json

os.makedirs("shared/raw", exist_ok=True)

cap = cv2.VideoCapture(0)

if not cap.isOpened():
    print("Error: Could not open webcam.")
    exit()

ret, prev_frame = cap.read()
if not ret:
    print("Error: Could not read frame.")
    exit()

prev_gray = cv2.cvtColor(prev_frame, cv2.COLOR_BGR2GRAY)
prev_gray = cv2.GaussianBlur(prev_gray, (21, 21), 0)

frame_id = 0

print("Motion Detection Started. Press 'ESC' to exit.")

while True:
    ret, frame = cap.read()
    if not ret:
        break

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    gray = cv2.GaussianBlur(gray, (21, 21), 0)

    frame_diff = cv2.absdiff(prev_gray, gray)
    thresh = cv2.threshold(frame_diff, 25, 255, cv2.THRESH_BINARY)[1]
    motion_score = int(thresh.sum())

    if motion_score > 500000:
        filename = f"shared/raw/frame_{frame_id}.jpg"
        meta_path = f"shared/raw/frame_{frame_id}.meta"

        cv2.imwrite(filename, frame)

        # Save motion metadata for context classification
        with open(meta_path, "w") as f:
            json.dump({
                "motion_score": motion_score,
                "timestamp": time.time()
            }, f)

        severity = "CRITICAL" if motion_score > 3000000 else "NORMAL"
        print(f"[{severity}] Score: {motion_score} -> {filename}")
        frame_id += 1
        time.sleep(0.5)

    prev_gray = gray.copy()

    cv2.imshow("Motion Detection (Host)", frame)
    if cv2.waitKey(1) == 27:
        break

cap.release()
cv2.destroyAllWindows()
