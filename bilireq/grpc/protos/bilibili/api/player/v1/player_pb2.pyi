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
class HeartbeatReply(google.protobuf.message.Message):
    """客户端心跳上报-响应"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    TS_FIELD_NUMBER: builtins.int
    ts: builtins.int
    """时间戳"""
    def __init__(
        self,
        *,
        ts: builtins.int = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["ts", b"ts"]) -> None: ...

global___HeartbeatReply = HeartbeatReply

@typing_extensions.final
class HeartbeatReq(google.protobuf.message.Message):
    """客户端心跳上报-请求"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SERVER_TIME_FIELD_NUMBER: builtins.int
    SESSION_FIELD_NUMBER: builtins.int
    MID_FIELD_NUMBER: builtins.int
    AID_FIELD_NUMBER: builtins.int
    CID_FIELD_NUMBER: builtins.int
    SID_FIELD_NUMBER: builtins.int
    EPID_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    SUB_TYPE_FIELD_NUMBER: builtins.int
    QUALITY_FIELD_NUMBER: builtins.int
    TOTAL_TIME_FIELD_NUMBER: builtins.int
    PAUSED_TIME_FIELD_NUMBER: builtins.int
    PLAYED_TIME_FIELD_NUMBER: builtins.int
    VIDEO_DURATION_FIELD_NUMBER: builtins.int
    PLAY_TYPE_FIELD_NUMBER: builtins.int
    NETWORK_TYPE_FIELD_NUMBER: builtins.int
    LAST_PLAY_PROGRESS_TIME_FIELD_NUMBER: builtins.int
    MAX_PLAY_PROGRESS_TIME_FIELD_NUMBER: builtins.int
    FROM_FIELD_NUMBER: builtins.int
    FROM_SPMID_FIELD_NUMBER: builtins.int
    SPMID_FIELD_NUMBER: builtins.int
    EPID_STATUS_FIELD_NUMBER: builtins.int
    PLAY_STATUS_FIELD_NUMBER: builtins.int
    USER_STATUS_FIELD_NUMBER: builtins.int
    ACTUAL_PLAYED_TIME_FIELD_NUMBER: builtins.int
    AUTO_PLAY_FIELD_NUMBER: builtins.int
    LIST_PLAY_TIME_FIELD_NUMBER: builtins.int
    DETAIL_PLAY_TIME_FIELD_NUMBER: builtins.int
    server_time: builtins.int
    """"""
    session: builtins.str
    """"""
    mid: builtins.int
    """用户 mid"""
    aid: builtins.int
    """稿件 avid"""
    cid: builtins.int
    """视频 cid"""
    sid: builtins.str
    """"""
    epid: builtins.int
    """"""
    type: builtins.str
    """"""
    sub_type: builtins.int
    """"""
    quality: builtins.int
    """"""
    total_time: builtins.int
    """"""
    paused_time: builtins.int
    """"""
    played_time: builtins.int
    """"""
    video_duration: builtins.int
    """"""
    play_type: builtins.str
    """"""
    network_type: builtins.int
    """"""
    last_play_progress_time: builtins.int
    """"""
    max_play_progress_time: builtins.int
    """"""
    from_spmid: builtins.str
    """"""
    spmid: builtins.str
    """"""
    epid_status: builtins.str
    """"""
    play_status: builtins.str
    """"""
    user_status: builtins.str
    """"""
    actual_played_time: builtins.int
    """"""
    auto_play: builtins.int
    """"""
    list_play_time: builtins.int
    """"""
    detail_play_time: builtins.int
    """"""
    def __init__(
        self,
        *,
        server_time: builtins.int = ...,
        session: builtins.str = ...,
        mid: builtins.int = ...,
        aid: builtins.int = ...,
        cid: builtins.int = ...,
        sid: builtins.str = ...,
        epid: builtins.int = ...,
        type: builtins.str = ...,
        sub_type: builtins.int = ...,
        quality: builtins.int = ...,
        total_time: builtins.int = ...,
        paused_time: builtins.int = ...,
        played_time: builtins.int = ...,
        video_duration: builtins.int = ...,
        play_type: builtins.str = ...,
        network_type: builtins.int = ...,
        last_play_progress_time: builtins.int = ...,
        max_play_progress_time: builtins.int = ...,
        from_spmid: builtins.str = ...,
        spmid: builtins.str = ...,
        epid_status: builtins.str = ...,
        play_status: builtins.str = ...,
        user_status: builtins.str = ...,
        actual_played_time: builtins.int = ...,
        auto_play: builtins.int = ...,
        list_play_time: builtins.int = ...,
        detail_play_time: builtins.int = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["actual_played_time", b"actual_played_time", "aid", b"aid", "auto_play", b"auto_play", "cid", b"cid", "detail_play_time", b"detail_play_time", "epid", b"epid", "epid_status", b"epid_status", "from", b"from", "from_spmid", b"from_spmid", "last_play_progress_time", b"last_play_progress_time", "list_play_time", b"list_play_time", "max_play_progress_time", b"max_play_progress_time", "mid", b"mid", "network_type", b"network_type", "paused_time", b"paused_time", "play_status", b"play_status", "play_type", b"play_type", "played_time", b"played_time", "quality", b"quality", "server_time", b"server_time", "session", b"session", "sid", b"sid", "spmid", b"spmid", "sub_type", b"sub_type", "total_time", b"total_time", "type", b"type", "user_status", b"user_status", "video_duration", b"video_duration"]) -> None: ...

global___HeartbeatReq = HeartbeatReq
