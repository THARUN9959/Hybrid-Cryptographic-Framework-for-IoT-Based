import os
import time
import json
from datetime import datetime
from collections import Counter
from typing import Set, Tuple

import cv2
from ultralytics import YOLO

# ============== CONFIGURATION ==============
CONFIDENCE_THRESHOLD = 0.5
EVENT_COOLDOWN = 2.0  # Seconds between unique events
FPS_WINDOW = 30  # Frames for averaging FPS
MODE_SWITCH_THRESHOLD = 5  # Frames before committing scene switch

IMPORTANT_OBJECTS_BY_MODE = {
    "indoor": {"person", "backpack", "bag", "knife", "gun", "dog", "cat"},
    "outdoor": {"person", "car", "truck", "bus", "motorcycle", "bicycle", "backpack", "bag", "knife", "gun", "dog", "cat"},
}

# Threat level classification
THREAT_LEVELS = {
    "person": "MEDIUM",
    "car": "LOW",
    "backpack": "MEDIUM",
    "bag": "MEDIUM",
    "knife": "HIGH",
    "gun": "CRITICAL",
    "bicycle": "LOW",
    "dog": "LOW",
    "cat": "LOW",
}

WEAPON_OBJECTS = {"knife", "gun"}
PET_OBJECTS = {"dog", "cat"}
CARRY_OBJECTS = {"bag", "backpack"}
TRAFFIC_OBJECTS = {"car", "truck", "bus", "motorcycle", "bicycle"}


def classify_threat(detected_objects: list, is_night: bool, low_light: bool, scene_mode: str) -> Tuple[str, str, str]:
    """Classify threat level and produce a short reasoning note."""
    if not detected_objects:
        return "NONE", "Detected: none", "No activity detected"

    obj_set = set(detected_objects)
    obj_counts = Counter(detected_objects)

    if obj_set & WEAPON_OBJECTS:
        reason = f"Detected: {', '.join(sorted(obj_set))}"
        return "CRITICAL", reason, "Potential weapon detected. Immediate attention required."

    if "person" in obj_set and (obj_set & CARRY_OBJECTS) and (is_night or low_light):
        reason = f"Detected: {', '.join(sorted(obj_set))}"
        return "HIGH", reason, "Person carrying item in low-visibility conditions."

    if obj_set.issubset(PET_OBJECTS):
        reason = f"Detected: {', '.join(sorted(obj_set))}"
        return "LOW", reason, "Pet-only movement appears normal."

    if scene_mode == "outdoor" and "person" in obj_set:
        people_count = obj_counts.get("person", 1)
        reason = f"Detected: person x{people_count}"

        traffic_objects = {"car", "truck", "bus", "motorcycle", "bicycle"}
        has_traffic = bool(obj_set & traffic_objects)

        if people_count >= 3 and (is_night or low_light):
            return "HIGH", reason, "Crowd detected outside during low-visibility period."
        if people_count >= 3:
            return "MEDIUM", reason, "Crowd activity detected outside."
        if has_traffic and (is_night or low_light):
            return "MEDIUM", reason, "Person near traffic in low-visibility conditions."
        if has_traffic:
            return "LOW", reason, "Typical outdoor roadside activity."
        if is_night or low_light:
            return "MEDIUM", reason, "Single-person outdoor activity in low visibility."
        return "LOW", reason, "Typical outdoor pedestrian activity."

    if "person" in obj_set:
        people_count = obj_counts.get("person", 1)
        reason = f"Detected: person x{people_count}"
        if is_night or low_light:
            return "HIGH", reason, "Human movement in low-visibility period."
        return "MEDIUM", reason, "Likely normal indoor human activity."
    
    threat_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    max_threat = "NONE"
    
    for obj in detected_objects:
        level = THREAT_LEVELS.get(obj, "LOW")
        if threat_order.get(level, 0) > threat_order.get(max_threat, 0):
            max_threat = level
    
    obj_str = ", ".join(sorted(set(detected_objects)))
    reason = f"Detected: {obj_str}"
    return max_threat, reason, "Routine object activity."


def environment_flags(frame) -> Tuple[bool, bool]:
    """Infer time and brightness context for better threat decisions."""
    hour = datetime.now().hour
    is_night = hour >= 21 or hour < 6

    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    mean_brightness = float(gray.mean())
    low_light = mean_brightness < 55.0
    return is_night, low_light


def infer_scene_mode(
    raw_detected_objects: list,
    current_mode: str,
    indoor_votes: int,
    outdoor_votes: int,
) -> Tuple[str, int, int]:
    """Infer indoor/outdoor mode from detections with hysteresis to avoid flicker."""
    has_traffic = bool(set(raw_detected_objects) & TRAFFIC_OBJECTS)

    if has_traffic:
        outdoor_votes = min(outdoor_votes + 1, MODE_SWITCH_THRESHOLD)
        indoor_votes = max(indoor_votes - 1, 0)
    else:
        indoor_votes = min(indoor_votes + 1, MODE_SWITCH_THRESHOLD)
        outdoor_votes = max(outdoor_votes - 1, 0)

    if outdoor_votes >= MODE_SWITCH_THRESHOLD:
        current_mode = "outdoor"
    elif indoor_votes >= MODE_SWITCH_THRESHOLD:
        current_mode = "indoor"

    return current_mode, indoor_votes, outdoor_votes


def build_event_text(detected_objects: list, is_night: bool, low_light: bool, scene_mode: str) -> str:
    """Build event text with threat and reasoning for downstream analysis."""
    counts = Counter(detected_objects)
    parts = []
    for label, count in sorted(counts.items()):
        if count == 1:
            parts.append(label)
        else:
            parts.append(f"{label} x{count}")
    
    threat_level, reason, note = classify_threat(detected_objects, is_night, low_light, scene_mode)
    visibility = "low_light" if low_light else "normal_light"
    period = "night" if is_night else "day"
    return (
        f"{reason} | Objects: {', '.join(parts)} | Threat: {threat_level} | "
        f"Context: {scene_mode},{period},{visibility} | LLM hint: {note}"
    )


def main():
    os.makedirs("shared/metadata", exist_ok=True)
    os.makedirs("shared/suspicious", exist_ok=True)
    os.makedirs("shared/raw", exist_ok=True)

    model = YOLO("yolov8n.pt")
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("Error: Could not open webcam.")
        return

    frame_id = 0
    event_id = 0
    last_detected: Set[str] = set()
    last_event_time = time.time()
    frame_times = []
    
    scene_mode = "indoor"
    indoor_votes = 0
    outdoor_votes = 0
    print("Intelligent YOLO detection started in auto scene mode. Press ESC to stop.")

    while True:
        frame_start = time.time()
        ret, frame = cap.read()
        if not ret:
            break

        results = model(frame, verbose=False)

        is_night, low_light = environment_flags(frame)

        # ===== STEP 1: Filter by confidence =====
        raw_detected_objects = []
        for r in results:
            for box in r.boxes:
                confidence = float(box.conf[0])
                if confidence < CONFIDENCE_THRESHOLD:
                    continue  # Skip low-confidence detections
                
                cls_id = int(box.cls[0])
                name = model.names.get(cls_id, str(cls_id))
                
                raw_detected_objects.append(name)

        # ===== STEP 2: Auto scene inference =====
        scene_mode, indoor_votes, outdoor_votes = infer_scene_mode(
            raw_detected_objects,
            scene_mode,
            indoor_votes,
            outdoor_votes,
        )
        important_objects = IMPORTANT_OBJECTS_BY_MODE[scene_mode]
        detected_objects = [name for name in raw_detected_objects if name in important_objects]

        # ===== STEP 3: Change detection (prevent spam) =====
        current_detected = set(detected_objects)
        current_time = time.time()
        
        # Only trigger if: (a) objects changed AND (b) cooldown exceeded
        if current_detected and current_detected != last_detected and (current_time - last_event_time >= EVENT_COOLDOWN):
            threat, reason, note = classify_threat(detected_objects, is_night, low_light, scene_mode)

            event_text = build_event_text(detected_objects, is_night, low_light, scene_mode)
            file_path = f"shared/metadata/event_{event_id:04d}.txt"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(event_text)

            # Keep a visual snapshot alongside each generated event.
            snapshot_path = f"shared/suspicious/event_{event_id:04d}.jpg"
            cv2.imwrite(snapshot_path, frame)

            # Feed Camera service pipeline by writing raw frame + metadata.
            raw_path = f"shared/raw/frame_{event_id:04d}.jpg"
            raw_meta_path = f"shared/raw/frame_{event_id:04d}.meta"
            cv2.imwrite(raw_path, frame)

            if threat == "CRITICAL":
                motion_score = 4000000
            elif threat == "HIGH":
                motion_score = 3200000
            else:
                motion_score = 1500000

            with open(raw_meta_path, "w", encoding="utf-8") as mf:
                json.dump({"motion_score": motion_score, "timestamp": current_time}, mf)

            print(f"NEW EVENT #{event_id}: {reason} | {threat} | {note}")
            print(f"  Snapshot saved: {snapshot_path}")
            print(f"  Raw frame queued: {raw_path}")
            
            event_id += 1
            last_event_time = current_time
            last_detected = current_detected

        # ===== STEP 4: Render annotated frame with metrics =====
        annotated = results[0].plot()
        
        # Calculate FPS
        frame_end = time.time()
        frame_time = frame_end - frame_start
        frame_times.append(frame_time)
        if len(frame_times) > FPS_WINDOW:
            frame_times.pop(0)
        
        avg_frame_time = sum(frame_times) / len(frame_times)
        fps = 1.0 / avg_frame_time if avg_frame_time > 0 else 0
        
        # Overlay metrics on frame
        cv2.putText(annotated, f"FPS: {fps:.1f}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
        cv2.putText(annotated, f"Events: {event_id} | Frames: {frame_id}", (10, 70), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
        cv2.putText(annotated, f"Objs: {len(detected_objects)} | Filter: {CONFIDENCE_THRESHOLD:.0%}", (10, 110), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
        status_text = "Night" if is_night else "Day"
        if low_light:
            status_text += " / LowLight"
        cv2.putText(annotated, status_text, (10, 150), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
        cv2.putText(annotated, f"Scene: {scene_mode}", (10, 190), cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 0), 2)
        
        cv2.imshow("YOLO Detection (Host) - Intelligent Filtered", annotated)
        frame_id += 1

        if cv2.waitKey(1) == 27:
            break

    cap.release()
    cv2.destroyAllWindows()
    
    # Summary
    print(f"\n{'='*60}")
    print("Detection Complete")
    print(f"   Total Frames: {frame_id}")
    print(f"   Intelligent Events: {event_id}")
    spam_reduction = ((frame_id - event_id) / frame_id * 100) if frame_id else 0.0
    print(f"   Spam Reduction: {spam_reduction:.1f}%")
    print(f"   Avg FPS: {fps:.1f}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()