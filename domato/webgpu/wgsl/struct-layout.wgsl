struct Inner {
  offset : vec2<u32>,
  weights : array<f32, 4>,
}

struct Nested {
  inner : Inner,
  tag : u32,
}

struct RuntimeList {
  count : u32,
  items : array<u32>,
}

struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
}

@group(0) @binding(0) var<storage, read> list : RuntimeList;
@group(0) @binding(1) var<storage, read_write> nested : Nested;
@group(0) @binding(2) var<uniform> eye : vec4<f32>;
@group(1) @binding(0) var<uniform> view : array<mat4x4<f32>, 4>;
@group(1) @binding(1) var<storage, read_write> matrixOut : array<mat4x4<f32>>;
@group(2) @binding(0) var cubeShadow : texture_depth_cube_array;
@group(2) @binding(1) var shadowSampler : sampler_comparison;
@group(2) @binding(2) var cubeColor : texture_cube_array<f32>;
@group(2) @binding(3) var colorSampler : sampler;

fn averageOf(m : mat4x4<f32>) -> f32 {
  var total : f32 = 0.0;
  for (var row = 0u; row < 4u; row = row + 1u) {
    total = total + dot(m[row], vec4<f32>(1.0));
  }
  return total / 16.0;
}

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let basis = view[0u];
  // this naga keeps matrix inverse in its IR only; the WGSL name table never binds it
  let biased = transpose(basis) * vec4<f32>(f32(vi), 0.5, 0.0, 1.0);
  out.clip = vec4<f32>(normalize(biased.xyz) * averageOf(basis), 1.0);
  out.color = vec4<f32>(f32(vi) * 0.25, eye.xyz);
  return out;
}

@fragment
fn fs(@location(0) color : vec4<f32>) -> @location(0) vec4<f32> {
  let sampled = textureSampleCompare(
    cubeShadow, shadowSampler, color.xyz, u32(color.w * 5.0) % 4u, 0.5);
  let lit = textureSample(cubeColor, colorSampler, color.xyz, u32(color.z * 3.0) % 4u);
  let det = determinant(view[1u]);
  return vec4<f32>(sampled + lit.r, f32(det), transpose(view[2u])[0].x, color.a);
}

@compute @workgroup_size(8, 1, 1)
fn cs(@builtin(local_invocation_id) lid : vec3<u32>) {
  let items = arrayLength(&list.items);
  let index = lid.x % items;
  let value = list.items[index] + nested.inner.offset.x;
  var weightSum : f32 = 0.0;
  for (var i = 0u; i < 4u; i = i + 1u) {
    weightSum = weightSum + nested.inner.weights[i] * f32(i);
  }
  let basis = view[lid.x % 4u];
  let transformed = basis * vec4<f32>(f32(value), weightSum, 0.0, 1.0);
  matrixOut[index] = basis * transpose(view[(lid.x + 1u) % 4u]);
  nested.tag = u32(transformed.x * 4.0);
}
