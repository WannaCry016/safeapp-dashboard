from sqlalchemy.orm import Session
from models import Device
from schemas.device import DeviceCreate

def upsert_device(db: Session, device_data: DeviceCreate):
    device = db.query(Device).filter(Device.device_id == device_data.device_id).first()
    if device:
        device.fcm_token = device_data.fcm_token
    else:
        device = Device(**device_data.dict())
        db.add(device)
    db.commit()
    db.refresh(device)
    return device
