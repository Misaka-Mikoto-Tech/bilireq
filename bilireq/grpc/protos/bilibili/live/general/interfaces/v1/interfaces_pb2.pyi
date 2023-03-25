"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.message
import sys

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing_extensions.final
class GetOnlineRankReq(google.protobuf.message.Message):
    """"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    RUID_FIELD_NUMBER: builtins.int
    ROOM_ID_FIELD_NUMBER: builtins.int
    PAGE_FIELD_NUMBER: builtins.int
    PAGE_SIZE_FIELD_NUMBER: builtins.int
    PLATFORM_FIELD_NUMBER: builtins.int
    ruid: builtins.int
    """"""
    room_id: builtins.int
    """"""
    page: builtins.int
    """"""
    page_size: builtins.int
    """"""
    platform: builtins.str
    """"""
    def __init__(
        self,
        *,
        ruid: builtins.int = ...,
        room_id: builtins.int = ...,
        page: builtins.int = ...,
        page_size: builtins.int = ...,
        platform: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["page", b"page", "page_size", b"page_size", "platform", b"platform", "room_id", b"room_id", "ruid", b"ruid"]) -> None: ...

global___GetOnlineRankReq = GetOnlineRankReq

@typing_extensions.final
class GetOnlineRankResp(google.protobuf.message.Message):
    """"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    @typing_extensions.final
    class OnlineRankItem(google.protobuf.message.Message):
        """"""

        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        UID_FIELD_NUMBER: builtins.int
        UNAME_FIELD_NUMBER: builtins.int
        FACE_FIELD_NUMBER: builtins.int
        CONTINUE_WATCH_FIELD_NUMBER: builtins.int
        MEDAL_INFO_FIELD_NUMBER: builtins.int
        GUARD_LEVEL_FIELD_NUMBER: builtins.int
        uid: builtins.int
        """"""
        uname: builtins.str
        """"""
        face: builtins.str
        """"""
        continue_watch: builtins.int
        """"""
        @property
        def medal_info(self) -> global___MedalInfo:
            """"""
        guard_level: builtins.int
        """"""
        def __init__(
            self,
            *,
            uid: builtins.int = ...,
            uname: builtins.str = ...,
            face: builtins.str = ...,
            continue_watch: builtins.int = ...,
            medal_info: global___MedalInfo | None = ...,
            guard_level: builtins.int = ...,
        ) -> None: ...
        def HasField(self, field_name: typing_extensions.Literal["medal_info", b"medal_info"]) -> builtins.bool: ...
        def ClearField(self, field_name: typing_extensions.Literal["continue_watch", b"continue_watch", "face", b"face", "guard_level", b"guard_level", "medal_info", b"medal_info", "uid", b"uid", "uname", b"uname"]) -> None: ...

    ITEM_FIELD_NUMBER: builtins.int
    ONLINE_NUM_FIELD_NUMBER: builtins.int
    @property
    def item(self) -> global___GetOnlineRankResp.OnlineRankItem:
        """"""
    online_num: builtins.int
    """"""
    def __init__(
        self,
        *,
        item: global___GetOnlineRankResp.OnlineRankItem | None = ...,
        online_num: builtins.int = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["item", b"item"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["item", b"item", "online_num", b"online_num"]) -> None: ...

global___GetOnlineRankResp = GetOnlineRankResp

@typing_extensions.final
class MedalInfo(google.protobuf.message.Message):
    """"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    GUARD_LEVEL_FIELD_NUMBER: builtins.int
    MEDAL_COLOR_START_FIELD_NUMBER: builtins.int
    MEDAL_COLOR_END_FIELD_NUMBER: builtins.int
    MEDAL_COLOR_BORDER_FIELD_NUMBER: builtins.int
    MEDAL_NAME_FIELD_NUMBER: builtins.int
    LEVEL_FIELD_NUMBER: builtins.int
    TARGET_ID_FIELD_NUMBER: builtins.int
    IS_LIGHT_FIELD_NUMBER: builtins.int
    guard_level: builtins.int
    """"""
    medal_color_start: builtins.int
    """"""
    medal_color_end: builtins.int
    """"""
    medal_color_border: builtins.int
    """"""
    medal_name: builtins.str
    """"""
    level: builtins.int
    """"""
    target_id: builtins.int
    """"""
    is_light: builtins.int
    """"""
    def __init__(
        self,
        *,
        guard_level: builtins.int = ...,
        medal_color_start: builtins.int = ...,
        medal_color_end: builtins.int = ...,
        medal_color_border: builtins.int = ...,
        medal_name: builtins.str = ...,
        level: builtins.int = ...,
        target_id: builtins.int = ...,
        is_light: builtins.int = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["guard_level", b"guard_level", "is_light", b"is_light", "level", b"level", "medal_color_border", b"medal_color_border", "medal_color_end", b"medal_color_end", "medal_color_start", b"medal_color_start", "medal_name", b"medal_name", "target_id", b"target_id"]) -> None: ...

global___MedalInfo = MedalInfo
