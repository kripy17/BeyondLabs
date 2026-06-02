from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.cyber_utils import (
    base64_encode,
    base64_decode,
    url_encode,
    url_decode,
    parse_url,
    decode_jwt,
    convert_timestamp,
)


router = APIRouter()


class TextRequest(BaseModel):
    text: str = Field(..., min_length=1)


class Base64Request(BaseModel):
    text: str = Field(..., min_length=1)
    action: Literal["encode", "decode"] = "decode"


class UrlCodecRequest(BaseModel):
    text: str = Field(..., min_length=1)
    action: Literal["encode", "decode"] = "decode"


class UrlParseRequest(BaseModel):
    url: str = Field(..., min_length=1)


class JwtDecodeRequest(BaseModel):
    token: str = Field(..., min_length=1)


class TimestampRequest(BaseModel):
    value: str = Field(..., min_length=1)


@router.post("/base64")
def base64_endpoint(request: Base64Request):
    if request.action == "encode":
        return base64_encode(request.text)

    return base64_decode(request.text)


@router.post("/url-codec")
def url_codec_endpoint(request: UrlCodecRequest):
    if request.action == "encode":
        return url_encode(request.text)

    return url_decode(request.text)


@router.post("/url-parse")
def url_parse_endpoint(request: UrlParseRequest):
    return parse_url(request.url)


@router.post("/jwt/decode")
def jwt_decode_endpoint(request: JwtDecodeRequest):
    return decode_jwt(request.token)


@router.post("/timestamp/convert")
def timestamp_convert_endpoint(request: TimestampRequest):
    return convert_timestamp(request.value)
