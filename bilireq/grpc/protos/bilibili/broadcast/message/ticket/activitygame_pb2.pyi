"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import sys
import typing

if sys.version_info >= (3, 10):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class _RoomStatus:
    ValueType = typing.NewType("ValueType", builtins.int)
    V: typing_extensions.TypeAlias = ValueType

class _RoomStatusEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[_RoomStatus.ValueType], builtins.type):
    DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
    Pause: _RoomStatus.ValueType  # 0
    """暂停:"""
    Play: _RoomStatus.ValueType  # 1
    """播放:"""
    End: _RoomStatus.ValueType  # 2
    """终止:"""

class RoomStatus(_RoomStatus, metaclass=_RoomStatusEnumTypeWrapper):
    """"""

Pause: RoomStatus.ValueType  # 0
"""暂停:"""
Play: RoomStatus.ValueType  # 1
"""播放:"""
End: RoomStatus.ValueType  # 2
"""终止:"""
global___RoomStatus = RoomStatus

@typing_extensions.final
class RoomEvent(google.protobuf.message.Message):
    """推送选项"""

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    ROOM_STATUS_FIELD_NUMBER: builtins.int
    ROOM_MESSAGE_FIELD_NUMBER: builtins.int
    room_status: global___RoomStatus.ValueType
    """RoomStatus 类型"""
    room_message: builtins.str
    """"""
    def __init__(
        self,
        *,
        room_status: global___RoomStatus.ValueType = ...,
        room_message: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["room_message", b"room_message", "room_status", b"room_status"]) -> None: ...

global___RoomEvent = RoomEvent
