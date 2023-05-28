import time
import hashlib
import re
from hashlib import md5
from typing import Any, Dict, Optional, Tuple, Union
from urllib.parse import urlencode

from httpx import AsyncClient
from httpx._models import Response
from httpx._types import HeaderTypes, ProxiesTypes, URLTypes

from .._typing import T_Auth
from ..auth import Auth
from ..exceptions import ResponseCodeError

DEFAULT_HEADERS = {
    "user-agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88"
        " Safari/537.36 Edg/87.0.664.60"
    ),
    "Referer": "https://www.bilibili.com/",
}
APPKEY = "4409e2ce8ffd12b8"
APPSEC = "59b43e04ad6965f34319062b478f83dd"
homepage_cookies: Dict[str, str] = {}


async def get_homepage_cookies(proxies=None):
    if not homepage_cookies:
        async with AsyncClient(proxies=proxies) as client:
            resp = await client.request(
                "GET",
                "https://www.bilibili.com/",
                headers=DEFAULT_HEADERS,
                follow_redirects=True,
            )
        resp.encoding = "utf-8"
        homepage_cookies.update(resp.cookies)
    return homepage_cookies


def _encrypt_params(params: Dict[str, Any], local_id: int = 0) -> Dict[str, Any]:
    params["local_id"] = local_id
    params["appkey"] = APPKEY
    params["ts"] = int(time.time())
    params["sign"] = md5(
        f"{urlencode(sorted(params.items()))}{APPSEC}".encode("utf-8")
    ).hexdigest()
    return params

# region sign params
_salt = None
# def getsalt() -> str:
#     '''
#     获取salt
#     ----------
#     获取wbi_img_url和wbi_sub_url的地址：https://api.bilibili.com/x/web-interface/nav    
#     wbi_img_url = json()['wbi_img']['img_url']   
#     wbi_sub_url = json()['wbi_img']['sub_url']
#     '''
#     wbi_img_url = 'https://i0.hdslb.com/bfs/wbi/9cd4224d4fe74c7e9d6963e2ef891688.png'
#     wbi_sub_url = 'https://i0.hdslb.com/bfs/wbi/263655ae2cad4cce95c9c401981b044a.png'
#     n = wbi_img_url.split('/')[-1].split('.')[0]
#     o = wbi_sub_url.split('/')[-1].split('.')[0]
#     return ''.join([(n+o)[i] for i in [46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49, 33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40, 61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11, 36, 20, 34, 44, 52]])[:32]

async def getsalt(*, proxies: ProxiesTypes = {"all://": None}):
    async with AsyncClient(proxies=proxies) as client:
        url = "https://api.bilibili.com/x/web-interface/nav"
        req = await client.request(
            "GET", url, headers=DEFAULT_HEADERS
        )
    con = req.json()
    img_url = con["data"]["wbi_img"]["img_url"]
    sub_url = con["data"]["wbi_img"]["sub_url"]
    # 伪装成了url，提取其中文件名
    re_rule = r'wbi/(.*?).png'
    img_key = "".join(re.findall(re_rule, img_url))
    sub_key = "".join(re.findall(re_rule, sub_url))

    n = img_key + sub_key  # 拼接两串值
    array = list(n)  # 拆分转arr
    order = [46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5,
             49, 33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7,
             16, 24, 55, 40, 61, 26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54,
             21, 56, 59, 6, 63, 57, 62, 11, 36, 20, 34, 44, 52]
    salt = ''.join([array[i] for i in order])[:32]  # 按照特定顺序混淆并取前32位
    return salt

async def sign(e: Union[str, dict]) -> Tuple[str, str]:
    '''传入参数字符串返回签名和时间tuple[w_rid,wts]
    -----------
    e:str格式：qn=32&fnver=0&fnval=4048&fourk=1&voice_balance=1&gaia_source=pre-load&avid=593238479&bvid=BV16q4y1k7mq&cid=486645610\n
    e:dict格式：{'qn': '32', 'fnver': '0', 'fnval': '4048', 'fourk': '1', 'voice_balance': '1', 'gaia_source': 'pre-load', 'avid': '593238479', 'bvid': 'BV16q4y1k7mq', 'cid': '486645610'}：
    '''
    global _salt
    wts = str(int(time.time()))
    if type(e) == str:
        a = (e+'&wts='+wts).split('&')
    elif type(e) == dict:
        e['wts'] = wts
        a = [f'{key}={value}' for key, value in e.items()]
    else:
        raise Exception(f'invalid type of e:{type(e)}')
    a.sort()
    if _salt is None:
        _salt = await getsalt()
    w_rid = hashlib.md5(('&'.join(a)+_salt).encode(encoding='utf-8')).hexdigest()
    return w_rid, wts

async def sign_params(params:Dict[str, Any]):
    params.pop('w_rid', '')
    params.pop('wts', '')

    params['token'] = params.get('token', '')
    params['platform'] = params.get('platform', 'web')
    params['web_location'] = params.get('web_location', 1550101)

    w_rid, wts = await sign(params)
    params['w_rid'] = w_rid
    params['wts'] = wts

# endregion 

async def _request(
    method: str,
    url: URLTypes,
    *,
    params: Optional[Dict[str, Any]] = None,
    cookies: Optional[Dict[str, Any]] = None,
    auth: T_Auth = None,
    reqtype: str = "app",
    headers: HeaderTypes = DEFAULT_HEADERS,
    proxies: ProxiesTypes = {"all://": None},
    **kwargs,
) -> Response:
    auth = Auth(auth)
    if params is None:
        params = {}
    if cookies is None:
        cookies = {}
    if reqtype.lower() == "app":
        params.update(auth.tokens)
        _encrypt_params(params)
    else:
        cookies.update(auth.cookies)
    cookies.update(await get_homepage_cookies(proxies))
    if '/wbi/' in str(url):
        await sign_params(params)
    async with AsyncClient(proxies=proxies) as client:
        resp = await client.request(
            method, url, headers=headers, params=params, cookies=cookies, **kwargs
        )
    resp.encoding = "utf-8"
    return resp


async def request(
    method: str, url: URLTypes, *, raw: bool = False, **kwargs
) -> Dict[str, Any]:
    raw_json: Dict[str, Any] = (await _request(method, url, **kwargs)).json()
    if raw:
        return raw_json
    if raw_json["code"] != 0:
        raise ResponseCodeError(
            code=raw_json["code"],
            msg=raw_json["message"],
            data=raw_json.get("data", None),
        )
    return raw_json["data"]


async def get(url: URLTypes, **kwargs):
    global _salt
    try:
        response = await request("GET", url, **kwargs)
    except ResponseCodeError as e:
        if e.code == -403:
            _salt = await getsalt()
            response = await request("GET", url, **kwargs)
        else:
            raise
    return response


async def post(url: URLTypes, **kwargs):
    global _salt
    try:
        response = await request("POST", url, **kwargs)
    except ResponseCodeError as e:
        if e.code == -403:
            _salt = await getsalt()
            response = await request("POST", url, **kwargs)
        else:
            raise
    return response
