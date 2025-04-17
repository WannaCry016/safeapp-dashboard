from pydantic import BaseModel

class DeviceBase(BaseModel):
    device_id: str
    fcm_token: str

class DeviceCreate(DeviceBase):
    pass

class DeviceOut(DeviceBase):
    class Config:
        orm_mode = True
