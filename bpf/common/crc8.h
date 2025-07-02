#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

// We could use a static table, but the 5.15 verifier can't handle
// variable indexes even if they are min/max bounds checked.
// So we use a giant switch instead.
#define CRC8_TABLE(idx)                                                                            \
    ({                                                                                             \
        u8 result = 0;                                                                             \
        switch ((idx) & 0xff) {                                                                    \
        case 0x00:                                                                                 \
            result = 0x00;                                                                         \
            break;                                                                                 \
        case 0x01:                                                                                 \
            result = 0x07;                                                                         \
            break;                                                                                 \
        case 0x02:                                                                                 \
            result = 0x0e;                                                                         \
            break;                                                                                 \
        case 0x03:                                                                                 \
            result = 0x09;                                                                         \
            break;                                                                                 \
        case 0x04:                                                                                 \
            result = 0x1c;                                                                         \
            break;                                                                                 \
        case 0x05:                                                                                 \
            result = 0x1b;                                                                         \
            break;                                                                                 \
        case 0x06:                                                                                 \
            result = 0x12;                                                                         \
            break;                                                                                 \
        case 0x07:                                                                                 \
            result = 0x15;                                                                         \
            break;                                                                                 \
        case 0x08:                                                                                 \
            result = 0x38;                                                                         \
            break;                                                                                 \
        case 0x09:                                                                                 \
            result = 0x3f;                                                                         \
            break;                                                                                 \
        case 0x0a:                                                                                 \
            result = 0x36;                                                                         \
            break;                                                                                 \
        case 0x0b:                                                                                 \
            result = 0x31;                                                                         \
            break;                                                                                 \
        case 0x0c:                                                                                 \
            result = 0x24;                                                                         \
            break;                                                                                 \
        case 0x0d:                                                                                 \
            result = 0x23;                                                                         \
            break;                                                                                 \
        case 0x0e:                                                                                 \
            result = 0x2a;                                                                         \
            break;                                                                                 \
        case 0x0f:                                                                                 \
            result = 0x2d;                                                                         \
            break;                                                                                 \
        case 0x10:                                                                                 \
            result = 0x70;                                                                         \
            break;                                                                                 \
        case 0x11:                                                                                 \
            result = 0x77;                                                                         \
            break;                                                                                 \
        case 0x12:                                                                                 \
            result = 0x7e;                                                                         \
            break;                                                                                 \
        case 0x13:                                                                                 \
            result = 0x79;                                                                         \
            break;                                                                                 \
        case 0x14:                                                                                 \
            result = 0x6c;                                                                         \
            break;                                                                                 \
        case 0x15:                                                                                 \
            result = 0x6b;                                                                         \
            break;                                                                                 \
        case 0x16:                                                                                 \
            result = 0x62;                                                                         \
            break;                                                                                 \
        case 0x17:                                                                                 \
            result = 0x65;                                                                         \
            break;                                                                                 \
        case 0x18:                                                                                 \
            result = 0x48;                                                                         \
            break;                                                                                 \
        case 0x19:                                                                                 \
            result = 0x4f;                                                                         \
            break;                                                                                 \
        case 0x1a:                                                                                 \
            result = 0x46;                                                                         \
            break;                                                                                 \
        case 0x1b:                                                                                 \
            result = 0x41;                                                                         \
            break;                                                                                 \
        case 0x1c:                                                                                 \
            result = 0x54;                                                                         \
            break;                                                                                 \
        case 0x1d:                                                                                 \
            result = 0x53;                                                                         \
            break;                                                                                 \
        case 0x1e:                                                                                 \
            result = 0x5a;                                                                         \
            break;                                                                                 \
        case 0x1f:                                                                                 \
            result = 0x5d;                                                                         \
            break;                                                                                 \
        case 0x20:                                                                                 \
            result = 0xe0;                                                                         \
            break;                                                                                 \
        case 0x21:                                                                                 \
            result = 0xe7;                                                                         \
            break;                                                                                 \
        case 0x22:                                                                                 \
            result = 0xee;                                                                         \
            break;                                                                                 \
        case 0x23:                                                                                 \
            result = 0xe9;                                                                         \
            break;                                                                                 \
        case 0x24:                                                                                 \
            result = 0xfc;                                                                         \
            break;                                                                                 \
        case 0x25:                                                                                 \
            result = 0xfb;                                                                         \
            break;                                                                                 \
        case 0x26:                                                                                 \
            result = 0xf2;                                                                         \
            break;                                                                                 \
        case 0x27:                                                                                 \
            result = 0xf5;                                                                         \
            break;                                                                                 \
        case 0x28:                                                                                 \
            result = 0xd8;                                                                         \
            break;                                                                                 \
        case 0x29:                                                                                 \
            result = 0xdf;                                                                         \
            break;                                                                                 \
        case 0x2a:                                                                                 \
            result = 0xd6;                                                                         \
            break;                                                                                 \
        case 0x2b:                                                                                 \
            result = 0xd1;                                                                         \
            break;                                                                                 \
        case 0x2c:                                                                                 \
            result = 0xc4;                                                                         \
            break;                                                                                 \
        case 0x2d:                                                                                 \
            result = 0xc3;                                                                         \
            break;                                                                                 \
        case 0x2e:                                                                                 \
            result = 0xca;                                                                         \
            break;                                                                                 \
        case 0x2f:                                                                                 \
            result = 0xcd;                                                                         \
            break;                                                                                 \
        case 0x30:                                                                                 \
            result = 0x90;                                                                         \
            break;                                                                                 \
        case 0x31:                                                                                 \
            result = 0x97;                                                                         \
            break;                                                                                 \
        case 0x32:                                                                                 \
            result = 0x9e;                                                                         \
            break;                                                                                 \
        case 0x33:                                                                                 \
            result = 0x99;                                                                         \
            break;                                                                                 \
        case 0x34:                                                                                 \
            result = 0x8c;                                                                         \
            break;                                                                                 \
        case 0x35:                                                                                 \
            result = 0x8b;                                                                         \
            break;                                                                                 \
        case 0x36:                                                                                 \
            result = 0x82;                                                                         \
            break;                                                                                 \
        case 0x37:                                                                                 \
            result = 0x85;                                                                         \
            break;                                                                                 \
        case 0x38:                                                                                 \
            result = 0xa8;                                                                         \
            break;                                                                                 \
        case 0x39:                                                                                 \
            result = 0xaf;                                                                         \
            break;                                                                                 \
        case 0x3a:                                                                                 \
            result = 0xa6;                                                                         \
            break;                                                                                 \
        case 0x3b:                                                                                 \
            result = 0xa1;                                                                         \
            break;                                                                                 \
        case 0x3c:                                                                                 \
            result = 0xb4;                                                                         \
            break;                                                                                 \
        case 0x3d:                                                                                 \
            result = 0xb3;                                                                         \
            break;                                                                                 \
        case 0x3e:                                                                                 \
            result = 0xba;                                                                         \
            break;                                                                                 \
        case 0x3f:                                                                                 \
            result = 0xbd;                                                                         \
            break;                                                                                 \
        case 0x40:                                                                                 \
            result = 0xc7;                                                                         \
            break;                                                                                 \
        case 0x41:                                                                                 \
            result = 0xc0;                                                                         \
            break;                                                                                 \
        case 0x42:                                                                                 \
            result = 0xc9;                                                                         \
            break;                                                                                 \
        case 0x43:                                                                                 \
            result = 0xce;                                                                         \
            break;                                                                                 \
        case 0x44:                                                                                 \
            result = 0xdb;                                                                         \
            break;                                                                                 \
        case 0x45:                                                                                 \
            result = 0xdc;                                                                         \
            break;                                                                                 \
        case 0x46:                                                                                 \
            result = 0xd5;                                                                         \
            break;                                                                                 \
        case 0x47:                                                                                 \
            result = 0xd2;                                                                         \
            break;                                                                                 \
        case 0x48:                                                                                 \
            result = 0xff;                                                                         \
            break;                                                                                 \
        case 0x49:                                                                                 \
            result = 0xf8;                                                                         \
            break;                                                                                 \
        case 0x4a:                                                                                 \
            result = 0xf1;                                                                         \
            break;                                                                                 \
        case 0x4b:                                                                                 \
            result = 0xf6;                                                                         \
            break;                                                                                 \
        case 0x4c:                                                                                 \
            result = 0xe3;                                                                         \
            break;                                                                                 \
        case 0x4d:                                                                                 \
            result = 0xe4;                                                                         \
            break;                                                                                 \
        case 0x4e:                                                                                 \
            result = 0xed;                                                                         \
            break;                                                                                 \
        case 0x4f:                                                                                 \
            result = 0xea;                                                                         \
            break;                                                                                 \
        case 0x50:                                                                                 \
            result = 0xb7;                                                                         \
            break;                                                                                 \
        case 0x51:                                                                                 \
            result = 0xb0;                                                                         \
            break;                                                                                 \
        case 0x52:                                                                                 \
            result = 0xb9;                                                                         \
            break;                                                                                 \
        case 0x53:                                                                                 \
            result = 0xbe;                                                                         \
            break;                                                                                 \
        case 0x54:                                                                                 \
            result = 0xab;                                                                         \
            break;                                                                                 \
        case 0x55:                                                                                 \
            result = 0xac;                                                                         \
            break;                                                                                 \
        case 0x56:                                                                                 \
            result = 0xa5;                                                                         \
            break;                                                                                 \
        case 0x57:                                                                                 \
            result = 0xa2;                                                                         \
            break;                                                                                 \
        case 0x58:                                                                                 \
            result = 0x8f;                                                                         \
            break;                                                                                 \
        case 0x59:                                                                                 \
            result = 0x88;                                                                         \
            break;                                                                                 \
        case 0x5a:                                                                                 \
            result = 0x81;                                                                         \
            break;                                                                                 \
        case 0x5b:                                                                                 \
            result = 0x86;                                                                         \
            break;                                                                                 \
        case 0x5c:                                                                                 \
            result = 0x93;                                                                         \
            break;                                                                                 \
        case 0x5d:                                                                                 \
            result = 0x94;                                                                         \
            break;                                                                                 \
        case 0x5e:                                                                                 \
            result = 0x9d;                                                                         \
            break;                                                                                 \
        case 0x5f:                                                                                 \
            result = 0x9a;                                                                         \
            break;                                                                                 \
        case 0x60:                                                                                 \
            result = 0x27;                                                                         \
            break;                                                                                 \
        case 0x61:                                                                                 \
            result = 0x20;                                                                         \
            break;                                                                                 \
        case 0x62:                                                                                 \
            result = 0x29;                                                                         \
            break;                                                                                 \
        case 0x63:                                                                                 \
            result = 0x2e;                                                                         \
            break;                                                                                 \
        case 0x64:                                                                                 \
            result = 0x3b;                                                                         \
            break;                                                                                 \
        case 0x65:                                                                                 \
            result = 0x3c;                                                                         \
            break;                                                                                 \
        case 0x66:                                                                                 \
            result = 0x35;                                                                         \
            break;                                                                                 \
        case 0x67:                                                                                 \
            result = 0x32;                                                                         \
            break;                                                                                 \
        case 0x68:                                                                                 \
            result = 0x1f;                                                                         \
            break;                                                                                 \
        case 0x69:                                                                                 \
            result = 0x18;                                                                         \
            break;                                                                                 \
        case 0x6a:                                                                                 \
            result = 0x11;                                                                         \
            break;                                                                                 \
        case 0x6b:                                                                                 \
            result = 0x16;                                                                         \
            break;                                                                                 \
        case 0x6c:                                                                                 \
            result = 0x03;                                                                         \
            break;                                                                                 \
        case 0x6d:                                                                                 \
            result = 0x04;                                                                         \
            break;                                                                                 \
        case 0x6e:                                                                                 \
            result = 0x0d;                                                                         \
            break;                                                                                 \
        case 0x6f:                                                                                 \
            result = 0x0a;                                                                         \
            break;                                                                                 \
        case 0x70:                                                                                 \
            result = 0x57;                                                                         \
            break;                                                                                 \
        case 0x71:                                                                                 \
            result = 0x50;                                                                         \
            break;                                                                                 \
        case 0x72:                                                                                 \
            result = 0x59;                                                                         \
            break;                                                                                 \
        case 0x73:                                                                                 \
            result = 0x5e;                                                                         \
            break;                                                                                 \
        case 0x74:                                                                                 \
            result = 0x4b;                                                                         \
            break;                                                                                 \
        case 0x75:                                                                                 \
            result = 0x4c;                                                                         \
            break;                                                                                 \
        case 0x76:                                                                                 \
            result = 0x45;                                                                         \
            break;                                                                                 \
        case 0x77:                                                                                 \
            result = 0x42;                                                                         \
            break;                                                                                 \
        case 0x78:                                                                                 \
            result = 0x6f;                                                                         \
            break;                                                                                 \
        case 0x79:                                                                                 \
            result = 0x68;                                                                         \
            break;                                                                                 \
        case 0x7a:                                                                                 \
            result = 0x61;                                                                         \
            break;                                                                                 \
        case 0x7b:                                                                                 \
            result = 0x66;                                                                         \
            break;                                                                                 \
        case 0x7c:                                                                                 \
            result = 0x73;                                                                         \
            break;                                                                                 \
        case 0x7d:                                                                                 \
            result = 0x74;                                                                         \
            break;                                                                                 \
        case 0x7e:                                                                                 \
            result = 0x7d;                                                                         \
            break;                                                                                 \
        case 0x7f:                                                                                 \
            result = 0x7a;                                                                         \
            break;                                                                                 \
        case 0x80:                                                                                 \
            result = 0x89;                                                                         \
            break;                                                                                 \
        case 0x81:                                                                                 \
            result = 0x8e;                                                                         \
            break;                                                                                 \
        case 0x82:                                                                                 \
            result = 0x87;                                                                         \
            break;                                                                                 \
        case 0x83:                                                                                 \
            result = 0x80;                                                                         \
            break;                                                                                 \
        case 0x84:                                                                                 \
            result = 0x95;                                                                         \
            break;                                                                                 \
        case 0x85:                                                                                 \
            result = 0x92;                                                                         \
            break;                                                                                 \
        case 0x86:                                                                                 \
            result = 0x9b;                                                                         \
            break;                                                                                 \
        case 0x87:                                                                                 \
            result = 0x9c;                                                                         \
            break;                                                                                 \
        case 0x88:                                                                                 \
            result = 0xb1;                                                                         \
            break;                                                                                 \
        case 0x89:                                                                                 \
            result = 0xb6;                                                                         \
            break;                                                                                 \
        case 0x8a:                                                                                 \
            result = 0xbf;                                                                         \
            break;                                                                                 \
        case 0x8b:                                                                                 \
            result = 0xb8;                                                                         \
            break;                                                                                 \
        case 0x8c:                                                                                 \
            result = 0xad;                                                                         \
            break;                                                                                 \
        case 0x8d:                                                                                 \
            result = 0xaa;                                                                         \
            break;                                                                                 \
        case 0x8e:                                                                                 \
            result = 0xa3;                                                                         \
            break;                                                                                 \
        case 0x8f:                                                                                 \
            result = 0xa4;                                                                         \
            break;                                                                                 \
        case 0x90:                                                                                 \
            result = 0xf9;                                                                         \
            break;                                                                                 \
        case 0x91:                                                                                 \
            result = 0xfe;                                                                         \
            break;                                                                                 \
        case 0x92:                                                                                 \
            result = 0xf7;                                                                         \
            break;                                                                                 \
        case 0x93:                                                                                 \
            result = 0xf0;                                                                         \
            break;                                                                                 \
        case 0x94:                                                                                 \
            result = 0xe5;                                                                         \
            break;                                                                                 \
        case 0x95:                                                                                 \
            result = 0xe2;                                                                         \
            break;                                                                                 \
        case 0x96:                                                                                 \
            result = 0xeb;                                                                         \
            break;                                                                                 \
        case 0x97:                                                                                 \
            result = 0xec;                                                                         \
            break;                                                                                 \
        case 0x98:                                                                                 \
            result = 0xc1;                                                                         \
            break;                                                                                 \
        case 0x99:                                                                                 \
            result = 0xc6;                                                                         \
            break;                                                                                 \
        case 0x9a:                                                                                 \
            result = 0xcf;                                                                         \
            break;                                                                                 \
        case 0x9b:                                                                                 \
            result = 0xc8;                                                                         \
            break;                                                                                 \
        case 0x9c:                                                                                 \
            result = 0xdd;                                                                         \
            break;                                                                                 \
        case 0x9d:                                                                                 \
            result = 0xda;                                                                         \
            break;                                                                                 \
        case 0x9e:                                                                                 \
            result = 0xd3;                                                                         \
            break;                                                                                 \
        case 0x9f:                                                                                 \
            result = 0xd4;                                                                         \
            break;                                                                                 \
        case 0xa0:                                                                                 \
            result = 0x69;                                                                         \
            break;                                                                                 \
        case 0xa1:                                                                                 \
            result = 0x6e;                                                                         \
            break;                                                                                 \
        case 0xa2:                                                                                 \
            result = 0x67;                                                                         \
            break;                                                                                 \
        case 0xa3:                                                                                 \
            result = 0x60;                                                                         \
            break;                                                                                 \
        case 0xa4:                                                                                 \
            result = 0x75;                                                                         \
            break;                                                                                 \
        case 0xa5:                                                                                 \
            result = 0x72;                                                                         \
            break;                                                                                 \
        case 0xa6:                                                                                 \
            result = 0x7b;                                                                         \
            break;                                                                                 \
        case 0xa7:                                                                                 \
            result = 0x7c;                                                                         \
            break;                                                                                 \
        case 0xa8:                                                                                 \
            result = 0x51;                                                                         \
            break;                                                                                 \
        case 0xa9:                                                                                 \
            result = 0x56;                                                                         \
            break;                                                                                 \
        case 0xaa:                                                                                 \
            result = 0x5f;                                                                         \
            break;                                                                                 \
        case 0xab:                                                                                 \
            result = 0x58;                                                                         \
            break;                                                                                 \
        case 0xac:                                                                                 \
            result = 0x4d;                                                                         \
            break;                                                                                 \
        case 0xad:                                                                                 \
            result = 0x4a;                                                                         \
            break;                                                                                 \
        case 0xae:                                                                                 \
            result = 0x43;                                                                         \
            break;                                                                                 \
        case 0xaf:                                                                                 \
            result = 0x44;                                                                         \
            break;                                                                                 \
        case 0xb0:                                                                                 \
            result = 0x19;                                                                         \
            break;                                                                                 \
        case 0xb1:                                                                                 \
            result = 0x1e;                                                                         \
            break;                                                                                 \
        case 0xb2:                                                                                 \
            result = 0x17;                                                                         \
            break;                                                                                 \
        case 0xb3:                                                                                 \
            result = 0x10;                                                                         \
            break;                                                                                 \
        case 0xb4:                                                                                 \
            result = 0x05;                                                                         \
            break;                                                                                 \
        case 0xb5:                                                                                 \
            result = 0x02;                                                                         \
            break;                                                                                 \
        case 0xb6:                                                                                 \
            result = 0x0b;                                                                         \
            break;                                                                                 \
        case 0xb7:                                                                                 \
            result = 0x0c;                                                                         \
            break;                                                                                 \
        case 0xb8:                                                                                 \
            result = 0x21;                                                                         \
            break;                                                                                 \
        case 0xb9:                                                                                 \
            result = 0x26;                                                                         \
            break;                                                                                 \
        case 0xba:                                                                                 \
            result = 0x2f;                                                                         \
            break;                                                                                 \
        case 0xbb:                                                                                 \
            result = 0x28;                                                                         \
            break;                                                                                 \
        case 0xbc:                                                                                 \
            result = 0x3d;                                                                         \
            break;                                                                                 \
        case 0xbd:                                                                                 \
            result = 0x3a;                                                                         \
            break;                                                                                 \
        case 0xbe:                                                                                 \
            result = 0x33;                                                                         \
            break;                                                                                 \
        case 0xbf:                                                                                 \
            result = 0x34;                                                                         \
            break;                                                                                 \
        case 0xc0:                                                                                 \
            result = 0x4e;                                                                         \
            break;                                                                                 \
        case 0xc1:                                                                                 \
            result = 0x49;                                                                         \
            break;                                                                                 \
        case 0xc2:                                                                                 \
            result = 0x40;                                                                         \
            break;                                                                                 \
        case 0xc3:                                                                                 \
            result = 0x47;                                                                         \
            break;                                                                                 \
        case 0xc4:                                                                                 \
            result = 0x52;                                                                         \
            break;                                                                                 \
        case 0xc5:                                                                                 \
            result = 0x55;                                                                         \
            break;                                                                                 \
        case 0xc6:                                                                                 \
            result = 0x5c;                                                                         \
            break;                                                                                 \
        case 0xc7:                                                                                 \
            result = 0x5b;                                                                         \
            break;                                                                                 \
        case 0xc8:                                                                                 \
            result = 0x76;                                                                         \
            break;                                                                                 \
        case 0xc9:                                                                                 \
            result = 0x71;                                                                         \
            break;                                                                                 \
        case 0xca:                                                                                 \
            result = 0x78;                                                                         \
            break;                                                                                 \
        case 0xcb:                                                                                 \
            result = 0x7f;                                                                         \
            break;                                                                                 \
        case 0xcc:                                                                                 \
            result = 0x6a;                                                                         \
            break;                                                                                 \
        case 0xcd:                                                                                 \
            result = 0x6d;                                                                         \
            break;                                                                                 \
        case 0xce:                                                                                 \
            result = 0x64;                                                                         \
            break;                                                                                 \
        case 0xcf:                                                                                 \
            result = 0x63;                                                                         \
            break;                                                                                 \
        case 0xd0:                                                                                 \
            result = 0x3e;                                                                         \
            break;                                                                                 \
        case 0xd1:                                                                                 \
            result = 0x39;                                                                         \
            break;                                                                                 \
        case 0xd2:                                                                                 \
            result = 0x30;                                                                         \
            break;                                                                                 \
        case 0xd3:                                                                                 \
            result = 0x37;                                                                         \
            break;                                                                                 \
        case 0xd4:                                                                                 \
            result = 0x22;                                                                         \
            break;                                                                                 \
        case 0xd5:                                                                                 \
            result = 0x25;                                                                         \
            break;                                                                                 \
        case 0xd6:                                                                                 \
            result = 0x2c;                                                                         \
            break;                                                                                 \
        case 0xd7:                                                                                 \
            result = 0x2b;                                                                         \
            break;                                                                                 \
        case 0xd8:                                                                                 \
            result = 0x06;                                                                         \
            break;                                                                                 \
        case 0xd9:                                                                                 \
            result = 0x01;                                                                         \
            break;                                                                                 \
        case 0xda:                                                                                 \
            result = 0x08;                                                                         \
            break;                                                                                 \
        case 0xdb:                                                                                 \
            result = 0x0f;                                                                         \
            break;                                                                                 \
        case 0xdc:                                                                                 \
            result = 0x1a;                                                                         \
            break;                                                                                 \
        case 0xdd:                                                                                 \
            result = 0x1d;                                                                         \
            break;                                                                                 \
        case 0xde:                                                                                 \
            result = 0x14;                                                                         \
            break;                                                                                 \
        case 0xdf:                                                                                 \
            result = 0x13;                                                                         \
            break;                                                                                 \
        case 0xe0:                                                                                 \
            result = 0xae;                                                                         \
            break;                                                                                 \
        case 0xe1:                                                                                 \
            result = 0xa9;                                                                         \
            break;                                                                                 \
        case 0xe2:                                                                                 \
            result = 0xa0;                                                                         \
            break;                                                                                 \
        case 0xe3:                                                                                 \
            result = 0xa7;                                                                         \
            break;                                                                                 \
        case 0xe4:                                                                                 \
            result = 0xb2;                                                                         \
            break;                                                                                 \
        case 0xe5:                                                                                 \
            result = 0xb5;                                                                         \
            break;                                                                                 \
        case 0xe6:                                                                                 \
            result = 0xbc;                                                                         \
            break;                                                                                 \
        case 0xe7:                                                                                 \
            result = 0xbb;                                                                         \
            break;                                                                                 \
        case 0xe8:                                                                                 \
            result = 0x96;                                                                         \
            break;                                                                                 \
        case 0xe9:                                                                                 \
            result = 0x91;                                                                         \
            break;                                                                                 \
        case 0xea:                                                                                 \
            result = 0x98;                                                                         \
            break;                                                                                 \
        case 0xeb:                                                                                 \
            result = 0x9f;                                                                         \
            break;                                                                                 \
        case 0xec:                                                                                 \
            result = 0x8a;                                                                         \
            break;                                                                                 \
        case 0xed:                                                                                 \
            result = 0x8d;                                                                         \
            break;                                                                                 \
        case 0xee:                                                                                 \
            result = 0x84;                                                                         \
            break;                                                                                 \
        case 0xef:                                                                                 \
            result = 0x83;                                                                         \
            break;                                                                                 \
        case 0xf0:                                                                                 \
            result = 0xde;                                                                         \
            break;                                                                                 \
        case 0xf1:                                                                                 \
            result = 0xd9;                                                                         \
            break;                                                                                 \
        case 0xf2:                                                                                 \
            result = 0xd0;                                                                         \
            break;                                                                                 \
        case 0xf3:                                                                                 \
            result = 0xd7;                                                                         \
            break;                                                                                 \
        case 0xf4:                                                                                 \
            result = 0xc2;                                                                         \
            break;                                                                                 \
        case 0xf5:                                                                                 \
            result = 0xc5;                                                                         \
            break;                                                                                 \
        case 0xf6:                                                                                 \
            result = 0xcc;                                                                         \
            break;                                                                                 \
        case 0xf7:                                                                                 \
            result = 0xcb;                                                                         \
            break;                                                                                 \
        case 0xf8:                                                                                 \
            result = 0xe6;                                                                         \
            break;                                                                                 \
        case 0xf9:                                                                                 \
            result = 0xe1;                                                                         \
            break;                                                                                 \
        case 0xfa:                                                                                 \
            result = 0xe8;                                                                         \
            break;                                                                                 \
        case 0xfb:                                                                                 \
            result = 0xef;                                                                         \
            break;                                                                                 \
        case 0xfc:                                                                                 \
            result = 0xfa;                                                                         \
            break;                                                                                 \
        case 0xfd:                                                                                 \
            result = 0xfd;                                                                         \
            break;                                                                                 \
        case 0xfe:                                                                                 \
            result = 0xf4;                                                                         \
            break;                                                                                 \
        case 0xff:                                                                                 \
            result = 0xf3;                                                                         \
            break;                                                                                 \
        default:                                                                                   \
            result = 0x00;                                                                         \
            break;                                                                                 \
        }                                                                                          \
        result;                                                                                    \
    })

static __always_inline u8 crc8(const unsigned char *data, u8 size) {
    u8 crc = 0x00;
    u8 idx;

#pragma clang loop unroll(full)
    for (u8 i = 0; i < size; i++) {
        idx = crc ^ data[i];
        crc = CRC8_TABLE(idx);
    }

    return crc;
}
