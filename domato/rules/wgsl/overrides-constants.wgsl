override overrideTiling : u32 = 2u;
override overrideScale : f32 = 1.5;
override overrideDepth : i32 = 2i;
override overrideCache : u32 = 4u;

struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) uv : vec2<f32>,
}

@group(0) @binding(0) var<uniform> params : vec4<f32>;
@group(0) @binding(1) var<storage, read_write> results : array<u32>;

var<workgroup> cache : array<u32, overrideCache>;

@vertex
fn vs(@builtin(vertex_index) vi : u32, @builtin(instance_index) ii : u32) -> VOut {
  var res : VOut;
  let span = f32(overrideTiling % 8u) * 0.125;
  let angle = f32(vi) * 2.094 + f32(ii) * span;
  res.clip = vec4<f32>(cos(angle) * overrideScale, sin(angle) * overrideScale, 0.0, 1.0);
  res.uv = vec2<f32>(0.5) + params.xy;
  return res;
}

@fragment
fn fs(@location(0) uv : vec2<f32>) -> @location(0) vec4<f32> {
  let steps = i32(overrideTiling) * overrideDepth;
  let scaled = uv * overrideScale;
  return vec4<f32>(scaled, f32(steps % 7i) * 0.2, 1.0) + params;
}

@compute @workgroup_size(4, 1, 1)
fn cs(@builtin(local_invocation_id) lid : vec3<u32>) {
  let tiles = overrideTiling * 2u;
  let level = overrideDepth + i32(lid.x);
  cache[lid.x % overrideCache] = tiles + u32(level);
  workgroupBarrier();
  switch (lid.x % 4u) {
    case 0u: { results[lid.x] = cache[0u] * overrideCache; }
    case 1u: { results[lid.x] = overrideCache; }
    default: { results[lid.x] = cache[lid.x % overrideCache] + u32(overrideScale * 100.0); }
  }
}
