use getrandom::Error;

fn my_entropy_source(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Ok(())
}

#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), Error> {
    let buf = unsafe {
        // fill the buffer with zeros
        core::ptr::write_bytes(dest, 0, len);
        // create mutable byte slice
        core::slice::from_raw_parts_mut(dest, len)
    };
    my_entropy_source(buf)
}
