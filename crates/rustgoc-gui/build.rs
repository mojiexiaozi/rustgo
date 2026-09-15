#[path = "src/app_icon.rs"]
mod app_icon;

fn main() {
    println!("cargo:rerun-if-changed=src/app_icon.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let sizes = [16u32, 32, 48, 64, 128];
    let mut images = Vec::new();
    for size in sizes {
        let pixels = app_icon::rgba(size);
        let mask_size = size.div_ceil(32) * 4 * size;
        let mut dib = Vec::new();
        for value in [40, size, size * 2] {
            dib.extend_from_slice(&value.to_le_bytes());
        }
        dib.extend_from_slice(&1u16.to_le_bytes());
        dib.extend_from_slice(&32u16.to_le_bytes());
        for value in [0u32, size * size * 4 + mask_size, 0, 0, 0, 0] {
            dib.extend_from_slice(&value.to_le_bytes());
        }
        for y in (0..size).rev() {
            for x in 0..size {
                let i = ((y * size + x) * 4) as usize;
                dib.extend_from_slice(&[pixels[i + 2], pixels[i + 1], pixels[i], pixels[i + 3]]);
            }
        }
        dib.resize(dib.len() + mask_size as usize, 0);
        images.push(dib);
    }
    let mut ico = vec![0, 0, 1, 0, sizes.len() as u8, 0];
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (size, image) in sizes.iter().zip(&images) {
        ico.extend_from_slice(&[*size as u8, *size as u8, 0, 0, 1, 0, 32, 0]);
        ico.extend_from_slice(&(image.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += image.len() as u32;
    }
    for image in images {
        ico.extend(image);
    }
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let icon = out.join("rustgo.ico");
    std::fs::write(&icon, ico).expect("write application icon");
    let rc = out.join("rustgo.rc");
    std::fs::write(
        &rc,
        format!(
            "1 ICON \"{}\"\n",
            icon.display().to_string().replace('\\', "/")
        ),
    )
    .expect("write icon resource");
    embed_resource::compile(&rc, embed_resource::NONE)
        .manifest_required()
        .expect("embed application icon");
}
