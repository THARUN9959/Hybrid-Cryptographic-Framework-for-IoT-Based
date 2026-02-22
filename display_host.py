import cv2
import os
import time

print("Monitoring shared/decrypted for new frames...")

while True:
    files = sorted(os.listdir("shared/decrypted"))

    for file in files:
        if file.endswith(".jpg"):
            path = f"shared/decrypted/{file}"
            img = cv2.imread(path)
            if img is not None:
                cv2.imshow("Decrypted Stream (Host)", img)
                print(f"Displaying: {file}")
                cv2.waitKey(100) # Show for 100ms
            
            # Optional: remove after displaying to keep folder clean? 
            # User didn't ask to remove, but it might fill up. I'll leave it for now.

    time.sleep(1)
