# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: pksyncbuf.proto

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)




DESCRIPTOR = _descriptor.FileDescriptor(
  name='pksyncbuf.proto',
  package='PkSyncDemo',
  serialized_pb='\n\x0fpksyncbuf.proto\x12\nPkSyncDemo\"\xee\x01\n\rPublicKeySync\x12\n\n\x02to\x18\x01 \x02(\t\x12\x0c\n\x04\x66rom\x18\x02 \x02(\t\x12H\n\x08\x64\x61taType\x18\x03 \x02(\x0e\x32+.PkSyncDemo.PublicKeySync.PublicKeySyncType:\tPK_UPDATE\x12\x0c\n\x04\x64\x61ta\x18\x04 \x01(\t\x12\x11\n\ttimestamp\x18\x05 \x02(\x05\"X\n\x11PublicKeySyncType\x12\r\n\tPK_UPDATE\x10\x00\x12\r\n\tSUBSCRIBE\x10\x01\x12\x0f\n\x0bUNSUBSCRIBE\x10\x02\x12\t\n\x05HELLO\x10\x03\x12\t\n\x05OTHER\x10\x04')



_PUBLICKEYSYNC_PUBLICKEYSYNCTYPE = _descriptor.EnumDescriptor(
  name='PublicKeySyncType',
  full_name='PkSyncDemo.PublicKeySync.PublicKeySyncType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='PK_UPDATE', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SUBSCRIBE', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='UNSUBSCRIBE', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='HELLO', index=3, number=3,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='OTHER', index=4, number=4,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=182,
  serialized_end=270,
)


_PUBLICKEYSYNC = _descriptor.Descriptor(
  name='PublicKeySync',
  full_name='PkSyncDemo.PublicKeySync',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='to', full_name='PkSyncDemo.PublicKeySync.to', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='from', full_name='PkSyncDemo.PublicKeySync.from', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='dataType', full_name='PkSyncDemo.PublicKeySync.dataType', index=2,
      number=3, type=14, cpp_type=8, label=2,
      has_default_value=True, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='data', full_name='PkSyncDemo.PublicKeySync.data', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='PkSyncDemo.PublicKeySync.timestamp', index=4,
      number=5, type=5, cpp_type=1, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _PUBLICKEYSYNC_PUBLICKEYSYNCTYPE,
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=32,
  serialized_end=270,
)

_PUBLICKEYSYNC.fields_by_name['dataType'].enum_type = _PUBLICKEYSYNC_PUBLICKEYSYNCTYPE
_PUBLICKEYSYNC_PUBLICKEYSYNCTYPE.containing_type = _PUBLICKEYSYNC;
DESCRIPTOR.message_types_by_name['PublicKeySync'] = _PUBLICKEYSYNC

class PublicKeySync(_message.Message):
  __metaclass__ = _reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _PUBLICKEYSYNC

  # @@protoc_insertion_point(class_scope:PkSyncDemo.PublicKeySync)


# @@protoc_insertion_point(module_scope)