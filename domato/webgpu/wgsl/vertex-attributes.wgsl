struct VertexIn {
  position : vec4<f32>,
  normal : vec3<f32>,
  tint : u32,
  uv : vec2<f32>,
}

struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
}

@group(0) @binding(0) var<uniform> viewProj : mat4x4<f32>;
@group(0) @binding(1) var<uniform> lightDir : vec4<f32>;
@group(0) @binding(2) var albedo : texture_2d<f32>;
@group(0) @binding(3) var pointSampler : sampler;
@group(0) @binding(4) var<storage, read_write> stats : array<atomic<u32>>;
@group(1) @binding(0) var emissive : texture_2d<f32>;
@group(1) @binding(1) var linearSampler : sampler;
@group(1) @binding(2) var<storage, read> palette : array<vec4<f32>, 16>;

fn unpackTint(packed : u32) -> vec4<f32> {
  return unpack4x8unorm(packed);
}

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var sample : VertexIn;
  sample.position = vec4<f32>(f32(vi) - 1.0, f32(vi % 2u), 0.0, 1.0);
  sample.normal = vec3<f32>(0.0, 1.0, 0.0);
  sample.tint = 255u;
  sample.uv = vec2<f32>(0.5);
  var out : VOut;
  out.clip = viewProj * sample.position;
  out.color = unpackTint(sample.tint) * vec4<f32>(sample.normal, 1.0);
  return out;
}

@fragment
fn fs(@location(0) color : vec4<f32>) -> @location(0) vec4<f32> {
  let base = textureSample(albedo, pointSampler, color.xy);
  let glow = textureSample(emissive, linearSampler, color.xy * 2.0);
  let diffuse = max(dot(normalize(color.xyz), normalize(lightDir.xyz)), 0.0);
  let tint = palette[u32(clamp(color.x, 0.0, 1.0) * 15.0)];
  return vec4<f32>(base.rgb * diffuse + glow.rgb * tint.a, base.a);
}

@compute @workgroup_size(16, 1, 1)
fn cs(@builtin(global_invocation_id) gid : vec3<u32>) {
  let hits = atomicAdd(&stats[gid.x], 1u);
  let previous = atomicCompareExchangeWeak(&stats[gid.x], hits, hits * 2u);
  let swapped = select(0u, previous.old_value, previous.exchanged);
  let negated = atomicSub(&stats[gid.x], swapped);
  let stored = atomicLoad(&stats[gid.x]);
  atomicStore(&stats[gid.x], bitcast<u32>(f32(stored) * 0.5));
  let cleared = atomicExchange(&stats[gid.x], negated);
  atomicStore(&stats[15u], cleared);
}
