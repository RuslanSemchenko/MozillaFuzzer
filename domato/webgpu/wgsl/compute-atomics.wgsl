struct Counters {
  total : atomic<u32>,
  signed_total : atomic<i32>,
  results : array<u32, 32>,
}

struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
}

@group(0) @binding(0) var<storage, read_write> counters : Counters;
@group(0) @binding(1) var<storage, read> source : array<f32>;
@group(0) @binding(2) var<uniform> limits : vec4<f32>;
@group(1) @binding(0) var<storage, read_write> output : array<vec4<f32>>;
@group(1) @binding(1) var depthTex : texture_depth_2d;
@group(1) @binding(2) var cmpSamp : sampler_comparison;

var<workgroup> tile : array<f32, 64>;
var<workgroup> tally : atomic<u32>;

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let angle = f32(vi) * 2.09f;
  out.clip = vec4<f32>(cos(angle), sin(angle), 0.0, 1.0);
  out.color = vec4<f32>(source[vi], limits.y, limits.z, 1.0);
  return out;
}

@fragment
fn fs(@location(0) color : vec4<f32>) -> @location(0) vec4<f32> {
  let coverage = textureSampleCompare(depthTex, cmpSamp, color.xy, 0.5);
  return vec4<f32>(color.rgb * coverage, color.a);
}

@compute @workgroup_size(16, 4, 1)
fn cs(@builtin(global_invocation_id) gid : vec3<u32>,
      @builtin(local_invocation_index) lid : u32) {
  tile[lid] = source[lid];
  workgroupBarrier();
  var partial : f32 = 0.0;
  for (var i = 0u; i < 64u; i = i + 1u) {
    partial = partial + tile[i];
  }
  atomicAdd(&tally, u32(partial));
  workgroupBarrier();
  let scaled = partial * limits.x;
  output[gid.x] = vec4<f32>(scaled, f32(atomicLoad(&tally)), 0.0, 1.0);
  atomicAdd(&counters.total, 1u);
  atomicAdd(&counters.signed_total, i32(scaled));
  counters.results[gid.x % 32u] = atomicLoad(&counters.total);
}

@compute @workgroup_size(8, 1, 1)
fn cs_reduce(@builtin(local_invocation_index) lid : u32) {
  tile[lid] = f32(lid);
  workgroupBarrier();
  var stride = 32u;
  loop {
    if (stride == 0u) {
      break;
    }
    if (lid < stride) {
      tile[lid] = tile[lid] + tile[lid + stride];
    }
    workgroupBarrier();
    stride = stride / 2u;
  }
  atomicStore(&counters.signed_total, atomicLoad(&counters.signed_total) + i32(tile[0]));
}
