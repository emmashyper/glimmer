//! LuaJIT bytecode field helpers (must match `vendor/LuaJIT/src/lj_bc.h`).

pub type BCIns = u32;

#[inline]
pub fn bc_op(ins: BCIns) -> u8 {
    (ins & 0xff) as u8
}

#[inline]
pub fn bc_a(ins: BCIns) -> u8 {
    ((ins >> 8) & 0xff) as u8
}

#[inline]
pub fn bc_b(ins: BCIns) -> u8 {
    ((ins >> 24) & 0xff) as u8
}

#[inline]
pub fn bc_c(ins: BCIns) -> u8 {
    ((ins >> 16) & 0xff) as u8
}

#[inline]
pub fn bc_d(ins: BCIns) -> u32 {
    ins >> 16
}

/// Opcode order from LuaJIT 2.1 `BCDEF` — `FUNCCW` = 96, `BC__MAX` = 97.
#[allow(dead_code)]
pub mod op {
    pub const FNEW: u8 = 51;
    pub const CAT: u8 = 38;
    pub const KSTR: u8 = 39;
    pub const KCDATA: u8 = 40;
    pub const GGET: u8 = 54;
    pub const GSET: u8 = 55;
    pub const TGETV: u8 = 56;
    pub const TGETS: u8 = 57;
    pub const TGETB: u8 = 58;
    pub const TGETR: u8 = 59;
    pub const TSETV: u8 = 60;
    pub const TSETS: u8 = 61;
    pub const TSETB: u8 = 62;
    pub const TSETM: u8 = 63;
    pub const TSETR: u8 = 64;
    pub const CALLM: u8 = 65;
    pub const CALL: u8 = 66;
    pub const CALLMT: u8 = 67;
    pub const CALLT: u8 = 68;
    pub const ITERC: u8 = 69;
    pub const ITERN: u8 = 70;
    pub const VARG: u8 = 71;
    pub const ISNEXT: u8 = 72;
    pub const FORI: u8 = 77;
    pub const JFORI: u8 = 78;
    pub const FORL: u8 = 79;
    pub const IFORL: u8 = 80;
    pub const JFORL: u8 = 81;
    pub const ITERL: u8 = 82;
    pub const IITERL: u8 = 83;
    pub const JITERL: u8 = 84;
    pub const LOOP: u8 = 85;
    pub const ILOOP: u8 = 86;
    pub const JLOOP: u8 = 87;
    pub const JFUNCF: u8 = 91;
    pub const JFUNCV: u8 = 94;
    pub const UCLO: u8 = 50;
    pub const MOV: u8 = 18;
    pub const UGET: u8 = 45;
    pub const POW: u8 = 37;
    pub const TNEW: u8 = 52;
    pub const TDUP: u8 = 53;
}
