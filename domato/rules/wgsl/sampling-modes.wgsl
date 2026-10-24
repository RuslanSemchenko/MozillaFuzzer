struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) uv : vec2<f32>,
  @location(1) @interpolate(flat, either) tint : vec2<u32>,
}

@group(0) @binding(0) var albedo : texture_2d<f32>;
@group(0) @binding(1) var samp : sampler;
@group(0) @binding(2) var vol : texture_3d<f32>;
@group(0) @binding(3) var line : texture_1d<f32>;
@group(0) @binding(4) var cubeFaces : texture_cube_array<f32>;
@group(0) @binding(5) var depthStack : texture_depth_2d_array;
@group(0) @binding(6) var cmpSamp : sampler_comparison;
@group(0) @binding(7) var<uniform> params : vec4<f32>;
@group(1) @binding(0) var<storage, read_write> extents : array<u32>;

@vertex
fn vs(@builtin(vertex_index) vi : u32, @builtin(instance_index) ii : u32) -> VOut {
  var out : VOut;
  let angle = f32(vi) * 2.094;
  out.clip = vec4<f32>(cos(angle), sin(angle), f32(ii) * 0.1, 1.0);
  out.uv = vec2<f32>(0.5) + params.xy;
  out.tint = vec2<u32>(ii, ii * 2u) + vec2<u32>(u32(vi));
  return out;
}

@fragment
fn fs(@location(0) uv : vec2<f32>, @location(1) @interpolate(flat, either) tint : vec2<u32>,
      @builtin(front_facing) front : bool) -> @location(0) vec4<f32> {
  let biased = textureSampleBias(albedo, samp, uv, params.w);
  let levelled = textureSampleLevel(albedo, samp, uv, params.w);
  let volume = textureSample(vol, samp, params.zww);
  let thin = textureSample(line, samp, uv.x);
  let face = textureSample(cubeFaces, samp, normalize(vec3<f32>(uv, 0.5)), tint.x % 6u);
  let cmp = textureGatherCompare(depthStack, cmpSamp, uv, tint.y % 4u, params.w);
  let grads = vec2<f32>(dpdx(biased.r), fwidth(levelled.g));
  let chosen = select(biased, levelled + thin, front);
  return chosen + vec4<f32>(volume.rgb, 1.0) + vec4<f32>(grads, 0.0, 0.0)
      + vec4<f32>(cmp) + face + vec4<f32>(grads.y);
}

@compute @workgroup_size(4, 1, 1)
fn cs(@builtin(local_invocation_index) lid : u32) {
  let dim = textureDimensions(albedo);
  let levels = textureNumLevels(vol);
  extents[lid] = u32(dim.x + levels) + u32(textureNumLevels(depthStack));
}
