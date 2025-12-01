```html
import math

BORDER_MARGIN = 25

def distance(p1, p2):
    dx = p1["x"] - p2["x"]
    dy = p1["y"] - p2["y"]
    return math.hypot(dx, dy)

def compute_angle(ship_pos, target_pos):
    # 0° = North, 90° = East, 180° = South, 270° = West
    dx = target_pos["x"] - ship_pos["x"]
    dy = target_pos["y"] - ship_pos["y"]
    angle_rad = math.atan2(dx, -dy)
    angle_deg = (math.degrees(angle_rad) + 360) % 360
    return angle_deg

def get_gate_point(island, sea_size, island_radius):
    x = island["position"]["x"]
    y = island["position"]["y"]
    t = island["type"]
    offset = island_radius * 2.5  # hơi xa đảo 1 chút

    if t == 1:  # East
        gx = min(x + offset, sea_size - BORDER_MARGIN)
        gy = y
    elif t == 2:  # South
        gx = x
        gy = min(y + offset, sea_size - BORDER_MARGIN)
    elif t == 3:  # West
        gx = max(x - offset, BORDER_MARGIN)
        gy = y
    elif t == 4:  # North
        gx = x
        gy = max(y - offset, BORDER_MARGIN)
    else:
        gx, gy = x, y

    return {"x": gx, "y": gy}

def pick_best_island(game_state, ship_pos):
    sea_size = game_state["sea_size"]
    islands = game_state["islands"]
    if not islands:
        return None

    # island_radius có thể có trong game_state hoặc từng island
    island_radius = game_state.get("island_radius", 10)

    best = None
    best_dist = float("inf")

    for idx, isl in enumerate(islands):
        if isl["validated"]:
            continue
        # ưu tiên radius trong island nếu có
        r = isl.get("radius", island_radius)
        gate = get_gate_point(isl, sea_size, r)
        d = distance(ship_pos, gate)
        if d < best_dist:
            best_dist = d
            best = {
                "target_type": "island",
                "index": idx,
                "target_pos": gate,
            }

    return best

def pick_best_barrel(game_state, ship_pos):
    barrels = game_state["barrels"]
    remaining = [b for b in barrels if not b["collected"]]
    if not remaining:
        return None

    best = None
    best_dist = float("inf")
    for idx, b in enumerate(remaining):
        pos = b["position"]
        d = distance(ship_pos, pos)
        if d < best_dist:
            best_dist = d
            best = {
                "target_type": "barrel",
                "index": idx,
                "target_pos": pos,
            }
    return best

def avoid_border(ship_pos, sea_size, current_target):
    x = ship_pos["x"]
    y = ship_pos["y"]

    near_left   = x < BORDER_MARGIN
    near_right  = x > sea_size - BORDER_MARGIN
    near_top    = y < BORDER_MARGIN
    near_bottom = y > sea_size - BORDER_MARGIN

    if near_left or near_right or near_top or near_bottom:
        center = {"x": sea_size / 2, "y": sea_size / 2}
        return {
            "target_type": "e",  # escape
            "index": -1,
            "target_pos": center,
        }
    return current_target

def compute_min_barrel_dist(game_state, ship_pos):
    barrels = game_state["barrels"]
    dmin = float("inf")
    for b in barrels:
        if b["collected"]:
            continue
        d = distance(ship_pos, b["position"])
        if d < dmin:
            dmin = d
    return dmin

def make_move(game_state):
    ship = game_state["your_ship"]
    ship_pos = ship["position"]
    ship_vel = ship["velocity"]
    sea_size = game_state["sea_size"]

    # ------ đọc memory từ data (stuck|cooldown) ------
    raw = game_state.get("data") or ""
    stuck = 0
    cool = 0
    try:
        parts = raw.split("|")
        if len(parts) == 2:
            stuck = int(parts[0])
            cool = int(parts[1])
    except Exception:
        stuck, cool = 0, 0

    # ------ cập nhật trạng thái kẹt gần barrel ------
    min_barrel_dist = compute_min_barrel_dist(game_state, ship_pos)
    speed = math.hypot(ship_vel["x"], ship_vel["y"])

    # nếu gần barrel và đi chậm -> tăng stuck
    if min_barrel_dist < 25 and speed < 5:
        stuck += 1
    else:
        stuck = max(0, stuck - 1)

    # giảm cooldown theo thời gian
    if cool > 0:
        cool -= 1

    # nếu stuck quá lâu -> bật cooldown, tạm bỏ qua barrel
    if stuck > 25:
        cool = 40
        stuck = 0

    # ------ chọn mục tiêu cơ bản ------
    island_target = pick_best_island(game_state, ship_pos)

    # nếu đang cooldown thì không pick barrel
    if cool > 0:
        barrel_target = None
    else:
        barrel_target = pick_best_barrel(game_state, ship_pos)

    if island_target is None and barrel_target is None:
        target_info = {
            "target_type": "i",  # idle
            "index": -1,
            "target_pos": {"x": sea_size / 2, "y": sea_size / 2},
        }
    elif island_target is None:
        target_info = barrel_target
        target_info["target_type"] = "b"
    elif barrel_target is None:
        target_info = island_target
        target_info["target_type"] = "a"
    else:
        # so sánh khoảng cách: cho phép ghé barrel nếu lợi
        dist_island = distance(ship_pos, island_target["target_pos"])
        dist_barrel = distance(ship_pos, barrel_target["target_pos"])
        if dist_barrel < dist_island * 0.6:
            target_info = barrel_target
            target_info["target_type"] = "b"
        else:
            target_info = island_target
            target_info["target_type"] = "a"

    # ------ tránh đâm biên ------
    target_info = avoid_border(ship_pos, sea_size, target_info)
    target_pos = target_info["target_pos"]

    # ------ tính góc ------
    angle = compute_angle(ship_pos, target_pos)

    # ------ điều khiển tốc độ ------
    speed = math.hypot(ship_vel["x"], ship_vel["y"])
    dist = distance(ship_pos, target_pos)

    if dist > 200:
        desired_speed = 18.0
    elif dist > 80:
        desired_speed = 12.0
    else:
        desired_speed = 6.0

    if speed < desired_speed * 0.8:
        acceleration = 100
    elif speed > desired_speed * 1.5:
        acceleration = -100
    else:
        acceleration = 50

    # ------ ghi lại memory (rất ngắn, <= 64 kí tự) ------
    data_str = f"{stuck}|{cool}"

    return {
        "acceleration": int(max(-100, min(100, acceleration))),
        "angle": int(angle) % 360,
        "data": data_str,
    }

```

<img width="480" height="445" alt="image" src="https://github.com/user-attachments/assets/b597fcb4-c010-4ca3-865c-e3c7381727e9" />
