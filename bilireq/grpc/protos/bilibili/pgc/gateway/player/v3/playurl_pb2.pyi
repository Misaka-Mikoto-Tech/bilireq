"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import bilireq.grpc.protos.bilibili.playershared.playershared_pb2
import builtins
import collections.abc
import google.protobuf.any_pb2
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.message
import sys

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing_extensions.final
class PlayViewReq(google.protobuf.message.Message):
    """播放页信息-请求"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    @typing_extensions.final
    class ExtraContentEntry(google.protobuf.message.Message):
        DESCRIPTOR: google.protobuf.descriptor.Descriptor

        KEY_FIELD_NUMBER: builtins.int
        VALUE_FIELD_NUMBER: builtins.int
        key: builtins.str
        value: builtins.str
        def __init__(
            self,
            *,
            key: builtins.str = ...,
            value: builtins.str = ...,
        ) -> None: ...
        def ClearField(self, field_name: typing_extensions.Literal["key", b"key", "value", b"value"]) -> None: ...

    VOD_FIELD_NUMBER: builtins.int
    SPMID_FIELD_NUMBER: builtins.int
    FROM_SPMID_FIELD_NUMBER: builtins.int
    TEENAGERS_MODE_FIELD_NUMBER: builtins.int
    EXTRA_CONTENT_FIELD_NUMBER: builtins.int
    @property
    def vod(self) -> bilireq.grpc.protos.bilibili.playershared.playershared_pb2.VideoVod:
        """视频信息"""
    spmid: builtins.str
    """当前页spm"""
    from_spmid: builtins.str
    """上一页spm"""
    teenagers_mode: builtins.int
    """青少年模式"""
    @property
    def extra_content(self) -> google.protobuf.internal.containers.ScalarMap[builtins.str, builtins.str]:
        """"""
    def __init__(
        self,
        *,
        vod: bilibili.playershared.playershared_pb2.VideoVod | None = ...,
        spmid: builtins.str = ...,
        from_spmid: builtins.str = ...,
        teenagers_mode: builtins.int = ...,
        extra_content: collections.abc.Mapping[builtins.str, builtins.str] | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["vod", b"vod"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["extra_content", b"extra_content", "from_spmid", b"from_spmid", "spmid", b"spmid", "teenagers_mode", b"teenagers_mode", "vod", b"vod"]) -> None: ...

global___PlayViewReq = PlayViewReq

@typing_extensions.final
class PlayViewReply(google.protobuf.message.Message):
    """播放页信息-响应"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    VOD_INFO_FIELD_NUMBER: builtins.int
    PLAY_ARC_CONF_FIELD_NUMBER: builtins.int
    SUPPLEMENT_FIELD_NUMBER: builtins.int
    PLAY_ARC_FIELD_NUMBER: builtins.int
    QN_TRIAL_INFO_FIELD_NUMBER: builtins.int
    EVENT_FIELD_NUMBER: builtins.int
    @property
    def vod_info(self) -> bilireq.grpc.protos.bilibili.playershared.playershared_pb2.VodInfo: ...
    @property
    def play_arc_conf(self) -> bilireq.grpc.protos.bilibili.playershared.playershared_pb2.PlayArcConf: ...
    @property
    def supplement(self) -> google.protobuf.any_pb2.Any: ...
    @property
    def play_arc(self) -> bilireq.grpc.protos.bilibili.playershared.playershared_pb2.PlayArc: ...
    @property
    def qn_trial_info(self) -> bilireq.grpc.protos.bilibili.playershared.playershared_pb2.QnTrialInfo: ...
    @property
    def event(self) -> bilireq.grpc.protos.bilibili.playershared.playershared_pb2.Event: ...
    def __init__(
        self,
        *,
        vod_info: bilibili.playershared.playershared_pb2.VodInfo | None = ...,
        play_arc_conf: bilibili.playershared.playershared_pb2.PlayArcConf | None = ...,
        supplement: google.protobuf.any_pb2.Any | None = ...,
        play_arc: bilibili.playershared.playershared_pb2.PlayArc | None = ...,
        qn_trial_info: bilibili.playershared.playershared_pb2.QnTrialInfo | None = ...,
        event: bilibili.playershared.playershared_pb2.Event | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["event", b"event", "play_arc", b"play_arc", "play_arc_conf", b"play_arc_conf", "qn_trial_info", b"qn_trial_info", "supplement", b"supplement", "vod_info", b"vod_info"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["event", b"event", "play_arc", b"play_arc", "play_arc_conf", b"play_arc_conf", "qn_trial_info", b"qn_trial_info", "supplement", b"supplement", "vod_info", b"vod_info"]) -> None: ...

global___PlayViewReply = PlayViewReply
