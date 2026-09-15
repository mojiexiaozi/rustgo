/// Shared artwork for the executable, window and notification-area icon.
pub fn rgba(size: u32) -> Vec<u8> {
    let glyph = [
        0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001,
    ];
    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let (x, y) = (x * 32 / size, y * 32 / size);
            let white = (8..23).contains(&x)
                && (5..26).contains(&y)
                && glyph[((y - 5) / 3) as usize] & (1 << (4 - (x - 8) / 3)) != 0;
            pixels.extend_from_slice(if white {
                &[255, 255, 255, 255]
            } else {
                &[30, 100, 210, 255]
            });
        }
    }
    pixels
}
