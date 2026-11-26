//! A small software renderer for the window tests' screenshots: egui's triangles drawn on the
//! CPU, so screenshots work on machines without a GPU (CI, containers). Not pixel-exact with
//! the real window, but the same layout, colours and text.

use std::collections::HashMap;

use eframe::egui::{self, Color32, TextureId, TexturesDelta, epaint};
use egui_kittest::TestRenderer;

#[derive(Default)]
pub struct Cpu {
    textures: HashMap<TextureId, (usize, usize, Vec<Color32>)>,
}

impl TestRenderer for Cpu {
    fn handle_delta(&mut self, delta: &mut TexturesDelta) {
        for (id, d) in delta
            .set
            .iter()
            .flat_map(|(id, ds)| ds.iter().map(move |d| (id, d)))
        {
            let egui::ImageData::Color(img) = &d.image;
            let [w, h] = img.size;
            match d.pos {
                None => {
                    self.textures.insert(*id, (w, h, img.pixels.clone()));
                }
                Some([x0, y0]) => {
                    if let Some((tw, _, px)) = self.textures.get_mut(id) {
                        for y in 0..h {
                            for x in 0..w {
                                px[(y0 + y) * *tw + x0 + x] = img.pixels[y * w + x];
                            }
                        }
                    }
                }
            }
        }
        for id in &delta.free {
            self.textures.remove(id);
        }
        delta.clear();
    }

    fn render(
        &mut self,
        ctx: &egui::Context,
        output: &egui::FullOutput,
    ) -> Result<image::RgbaImage, String> {
        let ppp = output.pixels_per_point;
        let screen = ctx.content_rect();
        let (w, h) = (
            (screen.width() * ppp).round() as usize,
            (screen.height() * ppp).round() as usize,
        );
        let mut buf = vec![[1.0f32, 1.0, 1.0, 1.0]; w * h];
        let prims = ctx.tessellate(output.shapes.clone(), ppp);
        for p in prims {
            let epaint::Primitive::Mesh(mesh) = &p.primitive else {
                continue;
            };
            let Some(tex) = self.textures.get(&mesh.texture_id) else {
                continue;
            };
            let clip = p.clip_rect;
            let (cx0, cy0) = (
                (clip.min.x * ppp).max(0.0) as i64,
                (clip.min.y * ppp).max(0.0) as i64,
            );
            let (cx1, cy1) = (
                ((clip.max.x * ppp).ceil() as i64).min(w as i64),
                ((clip.max.y * ppp).ceil() as i64).min(h as i64),
            );
            for tri in mesh.indices.as_chunks::<3>().0 {
                let v = [
                    &mesh.vertices[tri[0] as usize],
                    &mesh.vertices[tri[1] as usize],
                    &mesh.vertices[tri[2] as usize],
                ];
                triangle(&mut buf, w, v, ppp, tex, [cx0, cy0, cx1, cy1]);
            }
        }
        let mut img = image::RgbaImage::new(w as u32, h as u32);
        for (i, px) in img.pixels_mut().enumerate() {
            let c = buf[i];
            *px = image::Rgba([to8(c[0]), to8(c[1]), to8(c[2]), 255]);
        }
        Ok(img)
    }
}

fn to8(v: f32) -> u8 {
    (v.clamp(0.0, 1.0) * 255.0 + 0.5) as u8
}

fn triangle(
    buf: &mut [[f32; 4]],
    w: usize,
    v: [&epaint::Vertex; 3],
    ppp: f32,
    tex: &(usize, usize, Vec<Color32>),
    clip: [i64; 4],
) {
    let p: Vec<(f32, f32)> = v.iter().map(|v| (v.pos.x * ppp, v.pos.y * ppp)).collect();
    let area = (p[1].0 - p[0].0) * (p[2].1 - p[0].1) - (p[2].0 - p[0].0) * (p[1].1 - p[0].1);
    if area.abs() < 1e-6 {
        return;
    }
    let minx = (p.iter().map(|q| q.0).fold(f32::MAX, f32::min).floor() as i64).max(clip[0]);
    let maxx = (p.iter().map(|q| q.0).fold(f32::MIN, f32::max).ceil() as i64).min(clip[2]);
    let miny = (p.iter().map(|q| q.1).fold(f32::MAX, f32::min).floor() as i64).max(clip[1]);
    let maxy = (p.iter().map(|q| q.1).fold(f32::MIN, f32::max).ceil() as i64).min(clip[3]);
    let (tw, th, tp) = tex;
    for y in miny..maxy {
        for x in minx..maxx {
            let (px, py) = (x as f32 + 0.5, y as f32 + 0.5);
            let w0 = ((p[1].0 - px) * (p[2].1 - py) - (p[2].0 - px) * (p[1].1 - py)) / area;
            let w1 = ((p[2].0 - px) * (p[0].1 - py) - (p[0].0 - px) * (p[2].1 - py)) / area;
            let w2 = 1.0 - w0 - w1;
            if w0 < -1e-4 || w1 < -1e-4 || w2 < -1e-4 {
                continue;
            }
            let wt = [w0, w1, w2];
            let mut col = [0.0f32; 4];
            let (mut u, mut vv) = (0.0, 0.0);
            for k in 0..3 {
                let c = v[k].color.to_array();
                for i in 0..4 {
                    col[i] += wt[k] * c[i] as f32 / 255.0;
                }
                u += wt[k] * v[k].uv.x;
                vv += wt[k] * v[k].uv.y;
            }
            let tx = ((u * *tw as f32) as usize).min(tw - 1);
            let ty = ((vv * *th as f32) as usize).min(th - 1);
            let t = tp[ty * tw + tx].to_array();
            for i in 0..4 {
                col[i] *= t[i] as f32 / 255.0;
            }
            // premultiplied alpha over
            let d = &mut buf[y as usize * w + x as usize];
            for i in 0..3 {
                d[i] = col[i] + d[i] * (1.0 - col[3]);
            }
        }
    }
}
