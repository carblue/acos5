/*
 * iso7816.h: ISO-7816 defines
 */

pub const ISO7816_FILE_TYPE_TRANSPARENT_EF   : u8 =  0x01;
pub const ISO7816_FILE_TYPE_DF               : u8 =  0x38;

pub const ISO7816_TAG_FCI                    : u8 =  0x6F;

pub const ISO7816_TAG_FCP                    : u8 =  0x62;
pub const ISO7816_TAG_FCP_SIZE               : u8 =  0x80;
pub const ISO7816_TAG_FCP_SIZE_FULL          : u8 =  0x81; // not used by ACOS5
pub const ISO7816_TAG_FCP_TYPE               : u8 =  0x82;
pub const ISO7816_TAG_FCP_FID                : u8 =  0x83;
pub const ISO7816_TAG_FCP_DF_NAME            : u8 =  0x84;
pub const ISO7816_TAG_FCP_PROP_INFO          : u8 =  0x85; // not used by ACOS5
pub const ISO7816_TAG_FCP_ACLS               : u8 =  0x86; // not used by ACOS5
pub const ISO7816_TAG_FCP_LCS                : u8 =  0x8A;

/* ISO7816 interindustry data tags */                      // none of the following used by ACOS5
pub const ISO7816_II_CATEGORY_TLV            : u8 =  0x80;
pub const ISO7816_II_CATEGORY_NOT_TLV        : u8 =  0x00;

pub const ISO7816_TAG_II_CARD_SERVICE        : u8 =  0x43;
pub const ISO7816_TAG_II_INITIAL_ACCESS_DATA : u8 =  0x44;
pub const ISO7816_TAG_II_CARD_ISSUER_DATA    : u8 =  0x45;
pub const ISO7816_TAG_II_PRE_ISSUING         : u8 =  0x46;
pub const ISO7816_TAG_II_CARD_CAPABILITIES   : u8 =  0x47;
pub const ISO7816_TAG_II_AID                 : u8 =  0x4F;
pub const ISO7816_TAG_II_ALLOCATION_SCHEME   : u8 =  0x78;
pub const ISO7816_TAG_II_STATUS_LCS          : u8 =  0x81;
pub const ISO7816_TAG_II_STATUS_SW           : u8 =  0x82;
pub const ISO7816_TAG_II_STATUS_LCS_SW       : u8 =  0x83;
pub const ISO7816_TAG_II_EXTENDED_LENGTH     : u16 =  0x7F66;

pub const ISO7816_CAP_CHAINING               : u8 =  0x80;
pub const ISO7816_CAP_EXTENDED_LENGTH        : u8 =  0x40;
pub const ISO7816_CAP_EXTENDED_LENGTH_INFO   : u8 =  0x20;

/* Other interindustry data tags */
//pub const IASECC_TAG_II_IO_BUFFER_SIZES      : u8 =  0xE0;
