struct Frame {
  @align(16) view : mat4x4<f32>,
  @size(32) tags : vec2<u32>,
  time : f32,
}

struct VOut {
  @invariant @builtin(position) clip : vec4<f32>,
  @location(0) @interpolate(linear, centroid) shade : vec4<f32>,
  @location(1) @interpolate(flat, either) tag : u32,
}

@group(0) @binding(0) var<uniform> frame : Frame;
@group(0) @binding(1) var<storage, read_write> tally : array<u32>;
@group(1) @binding(0) var base : texture_2d<f32>;
@group(1) @binding(1) var baseSamp : sampler;
@group(2) @binding(0) var layers : texture_2d_array<f32>;
@group(2) @binding(1) var layerSamp : sampler;
@group(3) @binding(0) var shadow : texture_depth_2d;
@group(3) @binding(1) var shadowSamp : sampler_comparison;
@group(3) @binding(2) var<storage, read> palette : array<vec4<f32>>;

@vertex
fn vs(@builtin(vertex_index) vi : u32, @builtin(instance_index) ii : u32) -> VOut {
  var out : VOut;
  let angle = f32(vi + ii) * 0.7;
  out.clip = frame.view * vec4<f32>(cos(angle), sin(angle), 0.0, 1.0);
  out.shade = palette[(vi + ii) % arrayLength(&palette)] * frame.time;
  out.tag = frame.tags.x + ii;
  return out;
}

@fragment
fn fs(in : VOut) -> @location(0) vec4<f32> {
  let uv = in.shade.xy;
  let lit = textureSample(base, baseSamp, uv);
  let layer = textureSample(layers, layerSamp, uv, in.tag % 2u);
  let coverage = textureSampleCompare(shadow, shadowSamp, uv, in.shade.w);
  tally[in.tag % 8u] = u32(coverage * 4.0) + u32(lit.r + layer.g);
  return lit + layer + vec4<f32>(coverage);
}

@compute @workgroup_size(8, 1, 1)
fn cs(@builtin(local_invocation_index) lid : u32) {
  let dims = textureDimensions(shadow);
  let depth = textureLoad(shadow, vec2<i32>(i32(lid) % i32(dims.x), 0), 0u);
  let levels = textureNumLevels(base);
  tally[lid] = u32(depth * 255.0) + levels;
}
