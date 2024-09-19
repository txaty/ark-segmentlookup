// Number of rows: from 2^2 to 2^20
pub const N_VEC: [usize; 19] = [
    1 << 2,
    1 << 3,
    1 << 4,
    1 << 5,
    1 << 6,
    1 << 7,
    1 << 8,
    1 << 9,
    1 << 10,
    1 << 11,
    1 << 12,
    1 << 13,
    1 << 14,
    1 << 15,
    1 << 16,
    1 << 17,
    1 << 18,
    1 << 19,
    1 << 20,
];
// Number of columns: from 2^1 to 2^10
pub const S_VEC: [usize; 10] = [
    1 << 1,
    1 << 2,
    1 << 3,
    1 << 4,
    1 << 5,
    1 << 6,
    1 << 7,
    1 << 8,
    1 << 9,
    1 << 10,
];
// Number of executed segments: from 2^0 to 2^10
pub const K_VEC: [usize; 11] = [
    1 << 0,
    1 << 1,
    1 << 2,
    1 << 3,
    1 << 4,
    1 << 5,
    1 << 6,
    1 << 7,
    1 << 8,
    1 << 9,
    1 << 10,
];

pub const N_MID: usize = 1 << 14;
pub const S_MID: usize = 1 << 6;
pub const K_MID: usize = 1 << 4;
