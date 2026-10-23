struct Uniforms {
  scale : vec2<f32>,
  time : f32,
  steps : u32,
}

struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
}

@group(0) @binding(0) var<uniform> uni : Uniforms;
@group(0) @binding(1) var<storage, read_write> accum : array<u32>;
@group(0) @binding(2) var tex : texture_2d<f32>;
@group(0) @binding(3) var samp : sampler;

fn quantize(v : f32) -> u32 {
  return u32(clamp(v * 8.0, 0.0, 255.0));
}

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let x = f32(vi % 3u) * 2.0 - 1.0;
  out.clip = vec4<f32>(x * uni.scale.x, (f32(vi) - 1.0) * uni.scale.y, uni.time, 1.0);
  out.color = vec4<f32>(x, x * x, 0.5, 1.0);
  return out;
}

@fragment
fn fs(@location(0) color : vec4<f32>) -> @location(0) vec4<f32> {
  let sampled = textureSample(tex, samp, color.xy * 0.5 + vec2<f32>(0.25));
  return vec4<f32>(sampled.rgb + color.rgb, 1.0);
}

@compute @workgroup_size(8, 8, 1)
fn cs(@builtin(global_invocation_id) gid : vec3<u32>) {
  let index = gid.x + gid.y * 8u;
  accum[index] = accum[index] + 1u;
}

@compute @workgroup_size(4, 1, 1)
fn cs_bounded(@builtin(local_invocation_id) lid : vec3<u32>,
              @builtin(workgroup_id) wid : vec3<u32>) {
  let center = vec2<f32>(f32(wid.x), f32(wid.y)) + vec2<f32>(0.5);
  let offset = vec2<f32>(f32(lid.x) - 1.5, f32(lid.y) - 1.5);
  let dist = length(center + offset);
  accum[lid.x] = quantize(dist * uni.scale.x);
}
