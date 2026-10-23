struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) uv : vec2<f32>,
}

@group(0) @binding(0) var<uniform> extent : vec4<u32>;
@group(0) @binding(1) var<storage, read_write> counters : array<atomic<i32>>;
@group(1) @binding(0) var oneD : texture_storage_1d<r32float, read_write>;
@group(1) @binding(1) var twoD : texture_storage_2d<r32float, read_write>;
@group(2) @binding(0) var threeD : texture_storage_3d<rgba8sint, write>;
@group(2) @binding(2) var narrow : texture_storage_2d<rg32float, read>;
@group(3) @binding(0) var sampleable : texture_2d<f32>;
@group(3) @binding(1) var sampleSamp : sampler;

var<workgroup> totals : array<atomic<i32>, 4>;

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let angle = f32(vi) * 2.094;
  out.clip = vec4<f32>(cos(angle) * 0.8, sin(angle) * 0.8, 0.5, 1.0);
  out.uv = vec2<f32>(cos(angle) * 0.5 + 0.5, sin(angle) * 0.5 + 0.5);
  return out;
}

@fragment
fn fs(@location(0) uv : vec2<f32>) -> @location(0) vec4<f32> {
  let source = textureSample(sampleable, sampleSamp, uv);
  let column = i32(uv.x * f32(extent.x)) % 8;
  let row = i32(uv.y * f32(extent.y)) % 8;
  let previous = textureLoad(twoD, vec2<i32>(column, row));
  let restricted = textureLoad(narrow, vec2<i32>(row, column));
  textureStore(twoD, vec2<i32>(column, row), previous + source * 0.25);
  textureStore(oneD, column, vec4<f32>(f32(column) * 0.125, previous.r, source.b, 0.0));
  textureStore(threeD, vec3<i32>(column, row, i32(extent.z) / 2), vec4<i32>(source * 255.0));
  return previous + source + restricted;
}

@compute @workgroup_size(4, 1, 1)
fn cs(@builtin(local_invocation_id) lid : vec3<u32>) {
  let index = lid.x % 4u;
  atomicAdd(&totals[index], 1i);
  let rowWidth = textureDimensions(twoD).x;
  let columnHeight = textureDimensions(threeD).y;
  let span = textureDimensions(oneD);
  let accumulated = atomicLoad(&totals[index]);
  atomicStore(&counters[index], accumulated + i32(rowWidth + columnHeight + span));
  let scalar = textureLoad(oneD, i32(index) % 4);
  let stored = textureLoad(twoD, vec2<i32>(0, i32(index)));
  let wide = textureLoad(narrow, vec2<i32>(i32(index), 0));
  atomicAdd(&counters[index], i32(scalar.r * 8.0) + i32(stored.g * 8.0) + i32(wide.r));
}
