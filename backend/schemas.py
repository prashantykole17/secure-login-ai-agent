from __future__ import annotations

from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    sessionToken: str | None = None
    message: str = Field(min_length=1)


class LoginSimulationRequest(BaseModel):
    username: str
    password: str
    deviceId: str
    location: str


class VerifyOtpRequest(BaseModel):
    challengeId: int
    otpCode: str


class MobileOtpRequest(BaseModel):
    sessionToken: str | None = None
    phoneNumber: str
    purpose: str = "demo_mobile_otp"


class VerifyMobileOtpRequest(BaseModel):
    sessionToken: str | None = None
    phoneNumber: str
    otpCode: str


class ChatOtpLookupRequest(BaseModel):
    sessionToken: str | None = None
    phoneNumber: str


class HumanCheckRequest(BaseModel):
    sessionToken: str | None = None
    answer: str
    honeypot: str = ""
