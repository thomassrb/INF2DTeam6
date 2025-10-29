import uvicorn
import os
import time
import hashlib
import importlib
from datetime import datetime
from typing import Optional, List, Union
from functools import wraps
import json
import asyncio

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from jose import JWTError, jwt

from .storage_utils import load_user_data, save_user_data, db_init, load_json, load_parking_lot_data, save_parking_lot_data, load_reservation_data, save_reservation_data, load_vehicles_data, save_vehicles_data, load_parking_lot_sessions, save_parking_lot_sessions, load_payment_data, save_payment_data
from session_manager import add_session, get_session, remove_session, update_session_user
from models import UserRegister, UserLogin, UserProfileUpdate, SessionData, User, ParkingLotCreate, ParkingLotUpdate, VehicleCreate, VehicleUpdate, ReservationCreate, ReservationUpdate, PaymentCreate, PaymentRefund, PaymentUpdate, SessionStart, SessionStop, Session, ParkingLotSession
from tinydb import Query
import uuid
import session_calculator as sc


app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_RL_WINDOW_SEC = int(os.environ.get('MOBYPARK_RL_WINDOW_SEC', '60'))
_RL_IP_MAX = int(os.environ.get('MOBYPARK_RL_IP_MAX', '20'))
_RL_USER_MAX = int(os.environ.get('MOBYPARK_RL_USER_MAX', '10'))
_LOCKOUT_AFTER = int(os.environ.get('MOBYPARK_LOCKOUT_AFTER', '5'))
_LOCKOUT_SECONDS = int(os.environ.get('MOBYPARK_LOCKOUT_SECONDS', '300'))

_ip_attempts: dict = {}
_user_attempts: dict = {}
_ip_lockouts: dict = {}
_user_lockouts: dict = {}

def _now():
    return int(time.time())

def _prune_old(entries):
    cutoff = _now() - _RL_WINDOW_SEC
    return [t for t in entries if t >= cutoff]

async def _audit(session_user: Optional[User], action: str, *, target: Optional[str] = None, extra: Optional[dict] = None, status: str = "SUCCESS"):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(script_dir, '..', '..', 'data')
        os.makedirs(data_dir, exist_ok=True)
        log_path = os.path.join(data_dir, 'audit.log')
        entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": session_user.username if session_user else None,
            "role": session_user.role if session_user else None,
            "action": action,
            "target": target,
            "status": status,
            "extra": extra,
        }
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError:
        pass

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


_CORS_ORIGINS = [o.strip() for o in os.environ.get('MOBYPARK_CORS_ORIGINS', '').split(',') if o.strip()]
_CORS_ALLOW_HEADERS = os.environ.get('MOBYPARK_CORS_ALLOW_HEADERS', 'Authorization, Content-Type')
_CORS_ALLOW_METHODS = os.environ.get('MOBYPARK_CORS_ALLOW_METHODS', 'GET, POST, PUT, DELETE, OPTIONS')

if _CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"] if "*" in _CORS_ALLOW_METHODS else [m.strip() for m in _CORS_ALLOW_METHODS.split(',')],
        allow_headers=["*"] if "*" in _CORS_ALLOW_HEADERS else [h.strip() for h in _CORS_ALLOW_HEADERS.split(',')],
    )

async def _check_rate_limits_and_lockouts(request: Request, username: str):
    now = _now()
    ip = request.client.host if request.client else "unknown"

    ip_until = _ip_lockouts.get(ip)
    if isinstance(ip_until, int) and ip_until > now:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": "Too many attempts from IP. Try later.", "retry_after": max(1, ip_until - now)})
    user_until = _user_lockouts.get(username)
    if isinstance(user_until, int) and user_until > now:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": "Account temporarily locked. Try later.", "retry_after": max(1, user_until - now)})

    ip_entries = _prune_old(_ip_attempts.get(ip, []))
    _ip_attempts[ip] = ip_entries
    if len(ip_entries) >= _RL_IP_MAX:
        retry_after = max(1, (ip_entries[0] + _RL_WINDOW_SEC) - now)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": "Rate limit exceeded for IP.", "retry_after": retry_after})

    user_entries = _prune_old(_user_attempts.get(username, []))
    _user_attempts[username] = user_entries
    if len(user_entries) >= _RL_USER_MAX:
        retry_after = max(1, (user_entries[0] + _RL_WINDOW_SEC) - now)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail={"error": "Rate limit exceeded for user.", "retry_after": retry_after})

async def _record_login_attempt(request: Request, username: str, success: bool):
    now = _now()
    ip = request.client.host if request.client else "unknown"
    
    if success:
        _user_attempts.pop(username, None)
        _ip_attempts[ip] = _prune_old(_ip_attempts.get(ip, []))
        return

    ip_entries = _prune_old(_ip_attempts.get(ip, []))
    ip_entries.append(now)
    _ip_attempts[ip] = ip_entries

    user_entries = _prune_old(_user_attempts.get(username, []))
    user_entries.append(now)
    _user_attempts[username] = user_entries

    if _LOCKOUT_AFTER > 0 and len(user_entries) >= _LOCKOUT_AFTER:
        _user_lockouts[username] = now + _LOCKOUT_SECONDS
    if _LOCKOUT_AFTER > 0 and len(ip_entries) >= _LOCKOUT_AFTER:
        _ip_lockouts[ip] = now + _LOCKOUT_SECONDS


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    session_data = await get_session(token)
    if session_data is None:
        raise credentials_exception
    user_data = await asyncio.to_thread(load_user_data)
    user = next((u for u in user_data if u["username"] == session_data["username"]), None)
    if user is None:
        raise credentials_exception
    return User(**user)

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return current_user

async def get_current_active_admin_user(current_user: User = Depends(get_current_user)) -> User:
    if not current_user.active or current_user.role != "ADMIN":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not an active admin")
    return current_user


@app.get("/")
async def root():
    return {"message": "MobyPark API is running"}

@app.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegister):
    users = await asyncio.to_thread(load_user_data)
    if any(u["username"] == user_data.username for u in users):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already registered")

    hashed_password = get_password_hash(user_data.password)

    new_id = str(max((int(u.get("id", 0)) for u in users), default=0) + 1)
    new_user = User(
        id=new_id,
        username=user_data.username,
        password=hashed_password,
        name=user_data.name,
        phone=user_data.phone,
        email=user_data.email,
        birth_year=user_data.birth_year,
        role=user_data.role,
        active=True,
        created_at=datetime.now().strftime("%Y-%m-%d")
    )
    users.append(new_user.model_dump(by_alias=True, exclude_unset=True))
    await asyncio.to_thread(save_user_data, users)
    await _audit(None, action="register_user", target=user_data.username)
    return {"message": "User registered successfully"}


@app.post("/login", response_model=dict)
async def login_for_access_token(request: Request, form_data: UserLogin):
    await _check_rate_limits_and_lockouts(request, form_data.username)
    users = await asyncio.to_thread(load_user_data)
    user = next((u for u in users if u["username"] == form_data.username), None)

    if not user or not verify_password(form_data.password, user["password"]):
        await _record_login_attempt(request, form_data.username, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if _looks_like_md5(user.get("password", "")):
        new_hash = get_password_hash(form_data.password)
        user["password"] = new_hash
        user_db = await asyncio.to_thread(db_init, "users.json")
        await asyncio.to_thread(user_db.update, {"password": new_hash}, Query().username == form_data.username)

    token = str(uuid.uuid4())
    session_data = SessionData(**user)
    await add_session(token, session_data.model_dump())
    await _record_login_attempt(request, form_data.username, True)
    await _audit(User(**user), action="user_login")
    return {"message": "User logged in", "session_token": token}

@app.get("/logout", response_model=dict)
async def logout_user(current_user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme)):
    await remove_session(token)
    await _audit(current_user, action="user_logout")
    return {"message": "User logged out"}

@app.get("/profile", response_model=User)
async def get_profile(current_user: User = Depends(get_current_active_user)):
    await _audit(current_user, action="get_profile")
    return current_user

@app.put("/profile", response_model=dict)
async def update_profile(profile_update: UserProfileUpdate, current_user: User = Depends(get_current_active_user), token: str = Depends(oauth2_scheme)):
    users_db = await asyncio.to_thread(db_init, 'users.json')
    existing_user_doc = await asyncio.to_thread(users_db.get, Query().username == current_user.username)

    if not existing_user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found in DB")

    update_data = profile_update.model_dump(exclude_unset=True)
    if "password" in update_data:
        update_data["password"] = get_password_hash(update_data["password"])

    await asyncio.to_thread(users_db.update, update_data, Query().username == current_user.username)
    updated_user_dict = await asyncio.to_thread(users_db.get, Query().username == current_user.username)
    await update_session_user(token, updated_user_dict)
    await _audit(current_user, action="update_profile", target=current_user.username, extra=update_data)
    return {"message": "Profile updated successfully"}

@app.get("/profile/{user_id}", response_model=User)
async def get_profile_by_id(user_id: str, current_user: User = Depends(get_current_active_user)):
    users = await asyncio.to_thread(load_user_data)
    target_user = next((User(**u) for u in users if u.get("id") == user_id), None)

    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    is_admin = current_user.role == "ADMIN"
    if not is_admin and current_user.id != target_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You can only view your own profile.")
    
    await _audit(current_user, action="get_profile_by_id", target=user_id)
    return target_user

@app.put("/profile/{user_id}", response_model=dict)
async def update_profile_by_id(user_id: str, profile_update: UserProfileUpdate, current_user: User = Depends(get_current_active_admin_user), token: str = Depends(oauth2_scheme)):
    users_db = await asyncio.to_thread(db_init, 'users.json')
    existing_user_doc = await asyncio.to_thread(users_db.get, Query().id == user_id)

    if not existing_user_doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    update_data = profile_update.model_dump(exclude_unset=True)
    if "password" in update_data:
        update_data["password"] = get_password_hash(update_data["password"])
    
    await asyncio.to_thread(users_db.update, update_data, Query().id == user_id)
    updated_user_dict = await asyncio.to_thread(users_db.get, Query().id == user_id)
    if current_user.id == user_id:
        await update_session_user(token, updated_user_dict)

    await _audit(current_user, action="update_profile_by_id", target=user_id, extra=update_data)
    return {"message": "User profile updated successfully"}

@app.post("/parking-lots", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_parking_lot(parking_lot_data: ParkingLotCreate, current_user: User = Depends(get_current_active_admin_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    
    new_lid = str(max((int(lid) for lid in parking_lots.keys()), default=0) + 1)
    parking_lot_dict = parking_lot_data.model_dump()
    parking_lot_dict["id"] = new_lid
    parking_lot_dict["reserved"] = 0
    parking_lots[new_lid] = parking_lot_dict

    await asyncio.to_thread(save_parking_lot_data, parking_lots)
    await _audit(current_user, action="create_parking_lot", target=new_lid, extra=parking_lot_dict)
    return {"message": f"Parking lot saved under ID: {new_lid}"}

@app.get("/parking-lots", response_model=List[dict])
async def get_parking_lots():
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    return list(parking_lots.values())

@app.get("/parking-lots/{lid}", response_model=dict)
async def get_parking_lot_details(lid: str):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    parking_lot = parking_lots.get(lid)
    if not parking_lot:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    return parking_lot

@app.put("/parking-lots/{lid}", response_model=dict)
async def update_parking_lot(lid: str, parking_lot_update: ParkingLotUpdate, current_user: User = Depends(get_current_active_admin_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    update_data = parking_lot_update.model_dump()
    parking_lots[lid].update(update_data)
    await asyncio.to_thread(save_parking_lot_data, parking_lots)
    await _audit(current_user, action="update_parking_lot", target=lid, extra=update_data)
    return {"message": "Parking lot modified"}

@app.delete("/parking-lots/{lid}", response_model=dict)
async def delete_parking_lot(lid: str, current_user: User = Depends(get_current_active_admin_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    del parking_lots[lid]
    await asyncio.to_thread(save_parking_lot_data, parking_lots)
    await _audit(current_user, action="delete_parking_lot", target=lid)
    return {"message": f"Parking lot {lid} deleted"}

@app.post("/vehicles", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_vehicle(vehicle_data: VehicleCreate, current_user: User = Depends(get_current_active_user)):
    vehicles = await asyncio.to_thread(load_vehicles_data)
    users = await asyncio.to_thread(load_user_data)

    current_user_dict = next((u for u in users if u.get('username') == current_user.username), None)
    if not current_user_dict:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user_vehicles = [v for v in vehicles if v.get("user_id") == current_user_dict.get("id")]
    if any(v for v in user_vehicles if v.get('license_plate') == vehicle_data.licenseplate):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Vehicle already exists for this user")

    new_vid = str(uuid.uuid4())
    vehicle = {
        "id": new_vid,
        "user_id": current_user_dict.get('id'),
        "license_plate": vehicle_data.licenseplate,
        "name": vehicle_data.name,
        "created_at": datetime.now().strftime("%Y-%m-%d")
    }
    vehicles.append(vehicle)
    await asyncio.to_thread(save_vehicles_data, vehicles)
    await _audit(current_user, action="create_vehicle", target=new_vid, extra=vehicle)
    return {"status": "Success", "vehicle": vehicle}

@app.get("/vehicles", response_model=List[dict])
async def get_vehicles(current_user: User = Depends(get_current_active_user)):
    vehicles_data = await asyncio.to_thread(load_vehicles_data)

    if current_user.role == "ADMIN":
        return vehicles_data
    else:
        user_vehicles = [v for v in vehicles_data if v.get("user_id") == current_user.id]
        if not user_vehicles:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No vehicles found for this user")
        return user_vehicles

@app.get("/vehicles/{vid}", response_model=dict)
async def get_vehicle_details(vid: str, current_user: User = Depends(get_current_active_user)):
    vehicles_data = await asyncio.to_thread(load_vehicles_data)

    target_vehicle = next((v for v in vehicles_data if v.get("id") == vid), None)
    if not target_vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found")

    if current_user.role != "ADMIN" and target_vehicle.get("user_id") != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You can only view your own vehicle's details.")
    
    await _audit(current_user, action="get_vehicle_details", target=vid)
    return {"status": "Accepted", "vehicle": target_vehicle}

@app.put("/vehicles/{vid}", response_model=dict)
async def update_vehicle(vid: str, vehicle_update: VehicleUpdate, current_user: User = Depends(get_current_active_user)):
    vehicles_data = await asyncio.to_thread(load_vehicles_data)

    vehicle_found = False
    for i, v in enumerate(vehicles_data):
        if v.get('id') == vid:
            if current_user.role != "ADMIN" and v.get("user_id") != current_user.id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You can only update your own vehicles.")
            vehicles_data[i]["name"] = vehicle_update.name
            vehicles_data[i]["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            vehicle_found = True
            target_vehicle = vehicles_data[i]
            break
    
    if not vehicle_found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found")
    
    await asyncio.to_thread(save_vehicles_data, vehicles_data)
    await _audit(current_user, action="update_vehicle", target=vid, extra=vehicle_update.model_dump())
    return {"status": "Success", "vehicle": target_vehicle}

@app.delete("/vehicles/{vid}", response_model=dict)
async def delete_vehicle(vid: str, current_user: User = Depends(get_current_active_user)):
    vehicles_data = await asyncio.to_thread(load_vehicles_data)

    original_len = len(vehicles_data)
    updated_vehicles = []
    vehicle_to_delete = None

    for v in vehicles_data:
        if v.get('id') == vid:
            if current_user.role != "ADMIN" and v.get("user_id") != current_user.id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You can only delete your own vehicles.")
            vehicle_to_delete = v
        else:
            updated_vehicles.append(v)
    
    if len(updated_vehicles) == original_len:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found")
    
    await asyncio.to_thread(save_vehicles_data, updated_vehicles)
    await _audit(current_user, action="delete_vehicle", target=vid)
    return {"status": "Deleted", "vehicle": vehicle_to_delete}

@app.get("/vehicles/{license_plate}/reservations", response_model=List[dict])
async def get_vehicle_reservations_by_license_plate(license_plate: str, current_user: User = Depends(get_current_active_user)):
    vehicles_data = await asyncio.to_thread(load_vehicles_data)
    reservations_data = await asyncio.to_thread(load_reservation_data)

    target_vehicle = next((v for v in vehicles_data if v.get("license_plate") == license_plate), None)
    if not target_vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found")

    if current_user.role != "ADMIN" and target_vehicle.get("user_id") != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You can only view your own vehicle's reservations.")
    
    vehicle_reservations = [res for res in reservations_data.values() if res.get('licenseplate') == license_plate and res.get('user') == current_user.username]

    await _audit(current_user, action="get_vehicle_reservations", target=license_plate)
    return vehicle_reservations

@app.get("/vehicles/{license_plate}/history", response_model=List[dict])
async def get_vehicle_history(license_plate: str, current_user: User = Depends(get_current_active_user)):
    vehicles_data = await asyncio.to_thread(load_vehicles_data)
    reservations_data = await asyncio.to_thread(load_reservation_data)
    parking_lots = await asyncio.to_thread(load_parking_lot_data)

    target_vehicle = next((v for v in vehicles_data if v.get("license_plate") == license_plate), None)
    if not target_vehicle:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vehicle not found")

    if current_user.role != "ADMIN" and target_vehicle.get("user_id") != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied. You can only view your own vehicle's history.")

    history = []
    for res_data in reservations_data.values():
        if res_data.get("licenseplate") == license_plate:
            history.append({"type": "reservation", "data": res_data})

    for lid in parking_lots.keys():
        sessions_data = await asyncio.to_thread(load_parking_lot_sessions, lid)
        for sess_data in sessions_data:
            if sess_data.get("licenseplate") == license_plate and sess_data.get("user") == current_user.username:
                history.append({"type": "session", "data": sess_data})

    history.sort(key=lambda x: x["data"].get("startdate", x["data"].get("started", "")))

    await _audit(current_user, action="get_vehicle_history", target=license_plate)
    return history

@app.post("/reservations", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_reservation(reservation_data: ReservationCreate, current_user: User = Depends(get_current_active_user)):
    reservations = await asyncio.to_thread(load_reservation_data)
    parking_lots = await asyncio.to_thread(load_parking_lot_data)

    if reservation_data.parkinglot not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    if current_user.role != "ADMIN" and reservation_data.user and reservation_data.user != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Non-admin users cannot create reservations for other users")

    if not reservation_data.user:
        reservation_data.user = current_user.username
    
    new_rid = str(max((int(rid) for rid in reservations.keys()), default=0) + 1)
    reservation_dict = reservation_data.model_dump()
    reservation_dict["id"] = new_rid
    reservations[new_rid] = reservation_dict
    parking_lots[reservation_data.parkinglot]["reserved"] += 1

    await asyncio.to_thread(save_reservation_data, reservations)
    await asyncio.to_thread(save_parking_lot_data, parking_lots)
    await _audit(current_user, action="create_reservation", target=new_rid, extra=reservation_dict)
    return {"status": "Success", "reservation": reservation_dict}

@app.get("/reservations", response_model=List[dict])
async def get_reservations(current_user: User = Depends(get_current_active_user)):
    reservations = await asyncio.to_thread(load_reservation_data)
    if current_user.role == "ADMIN":
        return list(reservations.values())
    else:
        user_reservations = [res for res in reservations.values() if res.get("user") == current_user.username]
        return user_reservations

@app.get("/reservations/{rid}", response_model=dict)
async def get_reservation_details(rid: str, current_user: User = Depends(get_current_active_user)):
    reservations = await asyncio.to_thread(load_reservation_data)
    reservation = reservations.get(rid)

    if not reservation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reservation not found")

    if current_user.role != "ADMIN" and reservation.get("user") != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    await _audit(current_user, action="get_reservation_details", target=rid)
    return reservation

@app.put("/reservations/{rid}", response_model=dict)
async def update_reservation(rid: str, reservation_update: ReservationUpdate, current_user: User = Depends(get_current_active_user)):
    reservations = await asyncio.to_thread(load_reservation_data)
    parking_lots = await asyncio.to_thread(load_parking_lot_data)

    if rid not in reservations:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reservation not found")
    
    if current_user.role != "ADMIN" and reservations[rid].get("user") != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    if reservation_update.parkinglot not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")

    update_data = reservation_update.model_dump()
    reservations[rid].update(update_data)

    await asyncio.to_thread(save_reservation_data, reservations)
    await asyncio.to_thread(save_parking_lot_data, parking_lots)
    await _audit(current_user, action="update_reservation", target=rid, extra=update_data)
    return {"status": "Updated", "reservation": reservations[rid]}

@app.delete("/reservations/{rid}", response_model=dict)
async def delete_reservation(rid: str, current_user: User = Depends(get_current_active_user)):
    reservations = await asyncio.to_thread(load_reservation_data)
    parking_lots = await asyncio.to_thread(load_parking_lot_data)

    if rid not in reservations:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reservation not found")

    if current_user.role != "ADMIN" and reservations[rid].get("user") != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    reservation_to_delete = reservations[rid]
    pid = reservation_to_delete["parkinglot"]

    if parking_lots[pid]["reserved"] > 0:
        parking_lots[pid]["reserved"] -= 1
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Parking lot reserved count is already zero")

    del reservations[rid]
    await asyncio.to_thread(save_reservation_data, reservations)
    await asyncio.to_thread(save_parking_lot_data, parking_lots)
    await _audit(current_user, action="delete_reservation", target=rid)
    return {"status": "Deleted"}

@app.post("/parking-lots/{lid}/sessions/start", response_model=dict, status_code=status.HTTP_201_CREATED)
async def start_session(lid: str, session_start_data: SessionStart, current_user: User = Depends(get_current_active_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    sessions = await asyncio.to_thread(load_parking_lot_sessions, lid)
    filtered_sessions = [s for s in sessions if s.get("licenseplate") == session_start_data.licenseplate and not s.get("stopped")]
    
    if len(filtered_sessions) > 0:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot start a session when another session for this license plate is already started.")
    
    session_data = {
        "licenseplate": session_start_data.licenseplate,
        "started": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "stopped": None,
        "user": current_user.username
    }
    sessions.append(session_data)
    await asyncio.to_thread(save_parking_lot_sessions, lid, sessions)
    await _audit(current_user, action="start_session", target=lid, extra=session_data)
    return {"message": f"Session started for: {session_start_data.licenseplate}"}

@app.post("/parking-lots/{lid}/sessions/stop", response_model=dict)
async def stop_session(lid: str, session_stop_data: SessionStop, current_user: User = Depends(get_current_active_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")

    sessions = await asyncio.to_thread(load_parking_lot_sessions, lid)
    filtered_sessions = [s for s in sessions if s.get("licenseplate") == session_stop_data.licenseplate and not s.get("stopped")]

    if len(filtered_sessions) == 0:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Cannot stop a session when there is no session for this license plate.")

    session_to_stop = filtered_sessions[0]
    session_to_stop["stopped"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    
    for i, s in enumerate(sessions):
        if s.get("licenseplate") == session_stop_data.licenseplate and not s.get("stopped"):
            sessions[i] = session_to_stop
            break

    await asyncio.to_thread(save_parking_lot_sessions, lid, sessions)
    await _audit(current_user, action="stop_session", target=lid, extra=session_to_stop)
    return {"message": f"Session stopped for: {session_stop_data.licenseplate}"}

@app.get("/parking-lots/{lid}/sessions", response_model=List[dict])
async def get_parking_lot_sessions(lid: str, current_user: User = Depends(get_current_active_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    sessions = await asyncio.to_thread(load_parking_lot_sessions, lid)

    if current_user.role == "ADMIN":
        return sessions
    else:
        user_sessions = [s for s in sessions if s.get("user") == current_user.username]
        return user_sessions

@app.get("/parking-lots/{lid}/sessions/{sid}", response_model=dict)
async def get_parking_lot_session_details(lid: str, sid: str, current_user: User = Depends(get_current_active_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    sessions = await asyncio.to_thread(load_parking_lot_sessions, lid)
    session = next((s for s in sessions if str(s.doc_id) == sid), None)

    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    if current_user.role != "ADMIN" and session.get("user") != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    await _audit(current_user, action="get_session_details", target=f"{lid}/{sid}")
    return session

@app.delete("/parking-lots/{lid}/sessions/{sid}", response_model=dict)
async def delete_parking_lot_session(lid: str, sid: str, current_user: User = Depends(get_current_active_admin_user)):
    parking_lots = await asyncio.to_thread(load_parking_lot_data)
    if lid not in parking_lots:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parking lot not found")
    
    sessions = await asyncio.to_thread(load_parking_lot_sessions, lid)
    original_len = len(sessions)
    updated_sessions = [s for s in sessions if str(s.doc_id) != sid]

    if len(updated_sessions) == original_len:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    
    await asyncio.to_thread(save_parking_lot_sessions, lid, updated_sessions)
    await _audit(current_user, action="delete_session", target=f"{lid}/{sid}")
    return {"message": "Session deleted"}

@app.post("/payments", response_model=dict, status_code=status.HTTP_201_CREATED)
async def create_payment(payment_data: PaymentCreate, current_user: User = Depends(get_current_active_user)):
    payments = await asyncio.to_thread(load_payment_data)
    
    payment_dict = payment_data.model_dump()
    payment_dict["initiator"] = current_user.username
    payment_dict["created_at"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    payment_dict["completed"] = False
    payment_dict["completed_at"] = None
    payment_dict["hash"] = sc.generate_transaction_validation_hash()
    
    payments.append(payment_dict)
    await asyncio.to_thread(save_payment_data, payments)
    await _audit(current_user, action="create_payment", target=payment_dict["transaction"], extra={"amount": payment_dict["amount"], "coupled_to": payment_dict.get("coupled_to")})
    return {"status": "Success", "payment": payment_dict}

@app.post("/payments/refund", response_model=dict, status_code=status.HTTP_201_CREATED)
async def refund_payment(refund_data: PaymentRefund, current_user: User = Depends(get_current_active_admin_user)):
    payments = await asyncio.to_thread(load_payment_data)

    refund_txn = refund_data.transaction if refund_data.transaction else str(uuid.uuid4())
    payment_dict = refund_data.model_dump()
    payment_dict["transaction"] = refund_txn
    payment_dict["amount"] = -abs(refund_data.amount)
    payment_dict["processed_by"] = current_user.username
    payment_dict["created_at"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    payment_dict["completed"] = False
    payment_dict["completed_at"] = None
    payment_dict["hash"] = sc.generate_transaction_validation_hash()

    payments.append(payment_dict)
    await asyncio.to_thread(save_payment_data, payments)
    await _audit(current_user, action="refund_payment", target=refund_txn, extra={"amount": payment_dict["amount"], "coupled_to": payment_dict.get("coupled_to")})
    return {"status": "Success", "payment": payment_dict}

@app.get("/payments", response_model=List[dict])
async def get_payments(current_user: User = Depends(get_current_active_user)):
    payments = await asyncio.to_thread(load_payment_data)
    if current_user.role == "ADMIN":
        return payments
    else:
        user_payments = [p for p in payments if p.get("initiator") == current_user.username or p.get("processed_by") == current_user.username]
        return user_payments

@app.get("/payments/{pid}", response_model=dict)
async def get_payment_details(pid: str, current_user: User = Depends(get_current_active_user)):
    payments = await asyncio.to_thread(load_payment_data)
    payment = next((p for p in payments if p.get("transaction") == pid), None)

    if not payment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment not found!")
    
    if current_user.role != "ADMIN" and payment.get("initiator") != current_user.username and payment.get("processed_by") != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    await _audit(current_user, action="get_payment_details", target=pid)
    return payment

@app.put("/payments/{pid}", response_model=dict)
async def update_payment(pid: str, payment_update: PaymentUpdate, current_user: User = Depends(get_current_active_user)):
    payments_db = await asyncio.to_thread(db_init, 'payments.json')
    payment = await asyncio.to_thread(payments_db.get, Query().transaction == pid)

    if not payment:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Payment not found!")

    if current_user.role != "ADMIN" and payment.get("initiator") != current_user.username and payment.get("processed_by") != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    if payment["hash"] != payment_update.validation:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"error": "Validation failed", "info": "The validation of the security hash could not be validated for this transaction."})

    update_data = payment_update.model_dump(exclude_unset=True)
    payment["completed"] = True
    payment["completed_at"] = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    payment["t_data"] = update_data["t_data"]
    
    await asyncio.to_thread(payments_db.update, payment, Query().transaction == pid)
    await _audit(current_user, action="update_payment", target=pid)
    return {"status": "Success", "payment": payment}

@app.get("/billing", response_model=List[dict])
async def get_billing(current_user: User = Depends(get_current_active_user)):
    data = []
    parking_lots = await asyncio.to_thread(load_parking_lot_data)

    for pid, parkinglot in parking_lots.items():
        sessions = await asyncio.to_thread(load_parking_lot_sessions, pid)
        for sess_data in sessions:
            if sess_data.get("user") == current_user.username:
                amount, hours, days = sc.calculate_price(parkinglot, str(sess_data.doc_id), sess_data)
                transaction_hash = sc.generate_payment_hash(str(sess_data.doc_id), sess_data)
                payed = await asyncio.to_thread(sc.check_payment_amount, transaction_hash)
                data.append({
                    "session": {k: v for k, v in sess_data.items() if k in ["licenseplate", "started", "stopped"]} | {"hours": hours, "days": days},
                    "parking": {k: v for k, v in parkinglot.items() if k in ["name", "location", "hourly_rate", "day_rate"]},
                    "amount": amount,
                    "thash": transaction_hash,
                    "payed": payed,
                    "balance": amount - payed
                })
    await _audit(current_user, action="get_billing")
    return data

@app.get("/billing/{username}", response_model=List[dict])
async def get_user_billing(username: str, current_user: User = Depends(get_current_active_admin_user)):
    data = []
    parking_lots = await asyncio.to_thread(load_parking_lot_data)

    for pid, parkinglot in parking_lots.items():
        sessions = await asyncio.to_thread(load_parking_lot_sessions, pid)
        for sess_data in sessions:
            if sess_data.get("user") == username:
                amount, hours, days = sc.calculate_price(parkinglot, str(sess_data.doc_id), sess_data)
                transaction_hash = sc.generate_payment_hash(str(sess_data.doc_id), sess_data)
                payed = await asyncio.to_thread(sc.check_payment_amount, transaction_hash)
                data.append({
                    "session": {k: v for k, v in sess_data.items() if k in ["licenseplate", "started", "stopped"]} | {"hours": hours, "days": days},
                    "parking": {k: v for k, v in parkinglot.items() if k in ["name", "location", "hourly_rate", "day_rate"]},
                    "amount": amount,
                    "thash": transaction_hash,
                    "payed": payed,
                    "balance": amount - payed
                })
    await _audit(current_user, action="get_user_billing", target=username)
    return data


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
