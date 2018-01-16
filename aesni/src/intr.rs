use u64x2::u64x2;

extern {
    #[link_name = "llvm.x86.aesni.aesenc"]
    pub(crate) fn aesni_aesenc(a: u64x2, b: u64x2) -> u64x2;
    #[link_name = "llvm.x86.aesni.aesenclast"]
    pub(crate) fn aesni_aesenclast(a: u64x2, b: u64x2) -> u64x2;

    #[link_name = "llvm.x86.aesni.aesdec"]
    pub(crate) fn aesni_aesdec(a: u64x2, b: u64x2) -> u64x2;
    #[link_name = "llvm.x86.aesni.aesdeclast"]
    pub(crate) fn aesni_aesdeclast(a: u64x2, b: u64x2) -> u64x2;
}

macro_rules! round8 {
    ($op:expr, $data:expr, $key:expr) => {
        $data[0] = $op($data[0], $key);
        $data[1] = $op($data[1], $key);
        $data[2] = $op($data[2], $key);
        $data[3] = $op($data[3], $key);
        $data[4] = $op($data[4], $key);
        $data[5] = $op($data[5], $key);
        $data[6] = $op($data[6], $key);
        $data[7] = $op($data[7], $key);
    }
}
