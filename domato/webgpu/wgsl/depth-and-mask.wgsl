struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
  @location(1) @interpolate(flat) face : u32,
}

struct DepthOut {
  @location(0) color : vec4<f32>,
  @builtin(frag_depth) depth : f32,
  @builtin(sample_mask) mask : u32,
}

@group(0) @binding(0) var<uniform> camera : mat4x4<f32>;
@group(0) @binding(1) var intTex : texture_2d<i32>;
@group(0) @binding(2) var uintTex : texture_2d<u32>;
@group(0) @binding(3) var atomicTex : texture_2d<u32>;
@group(0) @binding(4) var writeTex : texture_storage_2d<rgba32sint, write>;
@group(0) @binding(5) var<storage, read_write> hits : array<u32>;
@group(1) @binding(0) var pointSamp : sampler;

var<workgroup> scratch : array<vec4<u32>, 8>;
var<workgroup> leader : u32;

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let radius = f32(vi % 3u) * 0.4 + 0.2;
  let angle = f32(vi) * 1.05;
  out.clip = camera * vec4<f32>(cos(angle) * radius, sin(angle) * radius, 0.0, 1.0);
  out.color = vec4<f32>(radius, f32(vi), 0.5, 1.0);
  out.face = vi / 3u;
  return out;
}

@fragment
fn fs(@location(0) color : vec4<f32>) -> @location(0) vec4<f32> {
  let coords = vec2<i32>(i32(color.x * 15.0), i32(color.y * 15.0));
  let signed = textureLoad(intTex, coords, 0u);
  let masked = textureLoad(uintTex, coords, 0u);
  textureStore(writeTex, coords, signed);
  hits[u32(color.w * 7.0) % 8u] = bitcast<u32>(color.r) + u32(signed.x) + masked.r;
  return vec4<f32>(color.rgb, 1.0);
}

@fragment
fn fs_depth(@location(0) color : vec4<f32>) -> DepthOut {
  var out : DepthOut;
  out.color = color;
  out.depth = clamp(color.x * 0.9 + 0.05, 0.0, 1.0);
  out.mask = select(0u, 0xFu, color.y > 0.5);
  return out;
}

@compute @workgroup_size(8, 1, 1)
fn cs(@builtin(local_invocation_index) lid : u32) {
  scratch[lid] = vec4<u32>(lid, lid * 2u, hits[lid], 1u);
  workgroupBarrier();
  if (lid == 0u) {
    leader = scratch[0].x + scratch[7].y;
  }
  workgroupBarrier();
  let broadcast = workgroupUniformLoad(&leader);
  hits[lid] = broadcast + scratch[lid].w;
}
