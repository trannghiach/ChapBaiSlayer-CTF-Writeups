```html
import math

BORDER_MARGIN = 25

def distance(p1, p2):
    dx = p1["x"] - p2["x"]
    dy = p1["y"] - p2["y"]
    return math.hypot(dx, dy)

def angle_from_vector(dx, dy):
    """
    Trả về góc theo hệ:
    - 0° = Bắc (y giảm)
    - 90° = Đông (x tăng)
    - 180° = Nam (y tăng)
    - 270° = Tây (x giảm)
    """
    angle_rad = math.atan2(dx, -dy)
    angle_deg = (math.degrees(angle_rad) + 360) % 360
    return angle_deg

def compute_angle(ship_pos, target_pos):
    dx = target_pos["x"] - ship_pos["x"]
    dy = target_pos["y"] - ship_pos["y"]
    return angle_from_vector(dx, dy)

def get_gate_point(island, sea_size, default_radius):
    x = island["position"]["x"]
    y = island["position"]["y"]
    t = island["type"]
    r = island.get("radius", default_radius)
    offset = r * 2.5  # lệch sang phía cần đi

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

def pick_best_barrel(game_state, ship_pos):
    barrels = game_state["barrels"]
    best = None
    best_dist = float("inf")
    for idx, b in enumerate(barrels):
        if b["collected"]:
            continue
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

def pick_best_island(game_state, ship_pos):
    sea_size = game_state["sea_size"]
    islands = game_state["islands"]
    if not islands:
        return None

    default_r = game_state.get("island_radius", 10)

    best = None
    best_dist = float("inf")
    for idx, isl in enumerate(islands):
        if isl["validated"]:
            continue
        gate = get_gate_point(isl, sea_size, default_r)
        d = distance(ship_pos, gate)
        if d < best_dist:
            best_dist = d
            best = {
                "target_type": "island",
                "index": idx,
                "target_pos": gate,
            }
    return best

def avoid_border(ship_pos, ship_vel, sea_size):
    """
    Nếu quá sát biên & đang bay ra ngoài -> override angle để quay vào trong.
    Trả về angle nếu cần override, ngược lại trả về None.
    """
    x = ship_pos["x"]
    y = ship_pos["y"]
    vx = ship_vel["x"]
    vy = ship_vel["y"]

    # sát trái mà còn bay sang trái -> quay sang phải
    if x < BORDER_MARGIN and vx < 0:
        return 90.0  # East
    # sát phải mà còn bay sang phải -> quay sang trái
    if x > sea_size - BORDER_MARGIN and vx > 0:
        return 270.0  # West
    # sát trên mà còn bay lên -> quay xuống
    if y < BORDER_MARGIN and vy < 0:
        return 180.0  # South
    # sát dưới mà còn bay xuống -> quay lên
    if y > sea_size - BORDER_MARGIN and vy > 0:
        return 0.0    # North

    return None

def make_move(game_state):
    ship = game_state["your_ship"]
    ship_pos = ship["position"]
    ship_vel = ship["velocity"]
    sea_size = game_state["sea_size"]

    # --- 1. chọn target: ưu tiên barrel, hết mới tới đảo ---
    target_info = pick_best_barrel(game_state, ship_pos)
    if target_info is None:
        target_info = pick_best_island(game_state, ship_pos)
    if target_info is None:
        # hết cả barrel lẫn đảo
        target_info = {
            "target_type": "idle",
            "index": -1,
            "target_pos": {"x": sea_size / 2, "y": sea_size / 2},
        }

    target_pos = target_info["target_pos"]

    # --- 2. khoảng cách & vận tốc ---
    dx = target_pos["x"] - ship_pos["x"]
    dy = target_pos["y"] - ship_pos["y"]
    dist = math.hypot(dx, dy)

    vx = ship_vel["x"]
    vy = ship_vel["y"]
    speed = math.hypot(vx, vy)

    # --- 3. border override (tránh nảy tường) ---
    border_angle = avoid_border(ship_pos, ship_vel, sea_size)

    # --- 4. điều khiển góc & acceleration ---
    if border_angle is not None:
        # ưu tiên quay đầu vào trong cho an toàn
        angle = border_angle
        acceleration = 100
    else:
        # khi RẤT GẦN target mà còn chạy nhanh -> quay ngược hướng velocity để phanh gấp
        if dist < 40 and speed > 4:
            if speed > 1e-6:
                # hướng ngược velocity
                angle = angle_from_vector(-vx, -vy)
            else:
                angle = compute_angle(ship_pos, target_pos)
            acceleration = 100
        else:
            # bình thường: aim vào target + control speed theo khoảng cách
            angle = compute_angle(ship_pos, target_pos)

            if target_info["target_type"] == "barrel":
                # barrel: ưu tiên rất nhanh khi xa, chậm hẳn khi gần
                if dist > 200:
                    desired_speed = 26.0
                elif dist > 80:
                    desired_speed = 16.0
                else:
                    desired_speed = 6.0
            else:
                # đảo / idle
                if dist > 250:
                    desired_speed = 24.0
                elif dist > 120:
                    desired_speed = 16.0
                else:
                    desired_speed = 8.0

            # thành phần vận tốc theo hướng target
            if dist > 1e-6:
                dir_x = dx / dist
                dir_y = dy / dist
                v_proj = vx * dir_x + vy * dir_y
            else:
                v_proj = 0.0

            if v_proj < desired_speed - 1.0:
                acceleration = 100
            elif v_proj > desired_speed + 1.0:
                acceleration = -100
            else:
                acceleration = 50

    return {
        "acceleration": int(max(-100, min(100, acceleration))),
        "angle": int(angle) % 360,
        "data": ""  # luôn dưới 64 ký tự
    }

```

<img width="632" height="561" alt="image" src="https://github.com/user-attachments/assets/51bf6cef-d343-43c7-9f45-93d17550982b" />
