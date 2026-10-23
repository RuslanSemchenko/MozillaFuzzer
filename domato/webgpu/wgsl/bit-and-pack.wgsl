struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) uv : vec2<f32>,
}

@group(0) @binding(0) var depthTex : texture_depth_2d;
@group(0) @binding(1) var cmpSamp : sampler_comparison;
@group(0) @binding(2) var colourTex : texture_2d<f32>;
@group(0) @binding(3) var linSamp : sampler;
@group(0) @binding(4) var<uniform> params : vec4<f32>;
@group(0) @binding(5) var<storage, read_write> out : array<atomic<u32>>;
@group(1) @binding(0) var layered : texture_storage_2d_array<rgba8uint, write>;

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var res : VOut;
  let angle = f32(vi) * 2.094;
  res.clip = vec4<f32>(cos(angle), sin(angle), 0.0, 1.0);
  res.uv = vec2<f32>(0.5) + params.xy;
  return res;
}

@fragment
fn fs(@location(0) uv : vec2<f32>, @builtin(front_facing) front : bool) -> @location(0) vec4<f32> {
  let depth = textureSampleCompare(depthTex, cmpSamp, uv, params.z);
  let level = textureSampleCompareLevel(depthTex, cmpSamp, uv, params.w);
  let gathered = textureGatherCompare(depthTex, cmpSamp, uv, params.z);
  let raw = textureGather(2u, colourTex, linSamp, uv);
  let halves = pack2x16float(vec2<f32>(depth, level));
  var back = unpack2x16float(halves);
  let bytes = unpack4x8snorm(pack4x8snorm(vec4<f32>(raw)));
  let split = modf(back.y + bytes.x);
  let parts = frexp(split.fract);
  let scaled = ldexp(split.whole, i32(u32(parts.exp) % 16u)) + fma(depth, level, params.w);
  let packed = select(halves, bitcast<u32>(scaled), front);
  textureStore(layered, vec2<i32>(i32(uv.x * 8.0), 0), u32(uv.y) % 2u, vec4<u32>(packed));
  return bytes + vec4<f32>(gathered) + vec4<f32>(f32(packed) * 0.01)
      + vec4<f32>(back.x, scaled, 0.0, 1.0);
}

@compute @workgroup_size(4, 1, 1)
fn cs(@builtin(local_invocation_id) lid : vec3<u32>) {
  let bits = reverseBits(bitcast<u32>(params.x)) ^ countOneBits(u32(params.w * 255.0));
  let high = i32(u32(firstLeadingBit(bitcast<i32>(params.y))) + firstTrailingBit(bits));
  let halves = pack2x16float(vec2<f32>(params.x, params.z));
  let back = unpack2x16float(halves);
  let split = modf(back.y);
  let parts = frexp(split.fract);
  let scaled = ldexp(split.whole, high % 16) + fma(params.z, params.w, back.x);
  let slices = textureNumLayers(layered);
  atomicAdd(&out[(lid.x + slices) % 4u],
          bitcast<u32>(scaled + parts.fract) + halves + u32(parts.exp) + bits);
}
