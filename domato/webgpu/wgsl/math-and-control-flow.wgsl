struct MathIn {
  a : vec3<f32>,
  b : vec3<f32>,
  m : mat3x3<f32>,
  seed : u32,
  packed : u32,
}

@group(0) @binding(0) var<uniform> input : MathIn;
@group(0) @binding(1) var<storage, read_write> results : array<u32>;
@group(0) @binding(2) var<storage, read_write> payload : array<i32>;
@group(1) @binding(0) var<uniform> thresholds : array<vec4<f32>, 2>;

fn rol32(value : u32, bits : u32) -> u32 {
  // no rotate builtin in WGSL: a rotate is a shift in each direction, merged
  // by a select so a zero shift keeps both sides valid.
  let masked = bits % 32u;
  return select((value << masked) | (value >> (32u - masked)), value, masked == 0u);
}

fn clampChannel(v : f32) -> f32 {
  return clamp(v, 0.0, 1.0);
}

fn quantize(v : f32) -> u32 {
  let scaled = clamp(v * 255.0, 0.0, 255.0);
  return u32(scaled);
}

@compute @workgroup_size(4, 4, 1)
fn cs(@builtin(local_invocation_id) lid : vec3<u32>) {
  let base = f32(lid.x + lid.y);
  let dotv = dot(input.a, input.b);
  let crossv = cross(input.a, input.b);
  let norm = normalize(input.a + input.b);
  let transformed = input.m * input.a;
  let refracted = refract(norm, normalize(input.b), 0.9);
  let mixed = mix(transformed, refracted, 0.25);
  var acc : f32 = 0.0;
  var i = 0u;
  while (i < 8u) {
    let value = thresholds[i / 4u][i % 4u];
    if (value > base) {
      acc = acc + value;
    } else if (value == base) {
      acc = acc - 1.0;
    } else {
      acc = acc * 0.5;
    }
    i = i + 1u;
  }
  let p = &input.seed;
  let rotated = rol32(input.packed, u32(acc)) ^ reverseBits(*p);
  let leading = countLeadingZeros(rotated);
  let lowest = u32(firstTrailingBit(rotated));
  let highest = u32(firstLeadingBit(rotated));
  let unpacked = unpack4x8snorm(input.packed);
  let result = quantize(acc + dotv + length(crossv) + mixed.x + clampChannel(mixed.y))
    + lowest + highest + leading + countTrailingZeros(rotated);
  results[lid.x + lid.y * 4u] = result;
  payload[lid.x] = i32(rotated);
  results[15u] = quantize(unpacked.z + f32(select(0, 1, rotated > 1u)));
}

struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
}

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let stepped = smoothstep(0.0, 1.0, f32(vi) / 3.0);
  out.clip = vec4<f32>(stepped * 2.0 - 1.0, stepped - 0.5, 0.0, 1.0);
  out.color = vec4<f32>(stepped, input.a.x, input.b.y, 1.0);
  return out;
}

@fragment
fn fs(@location(0) tint : vec4<f32>) -> @location(0) vec4<f32> {
  let dy = dpdy(tint.x);
  let face = faceForward(tint.xyz, vec3<f32>(0.0, 1.0, 0.0), vec3<f32>(0.0, 0.0, -1.0));
  let packed = pack4x8unorm(vec4<f32>(tint.rgb, dy));
  let bits = countOneBits(packed) + countOneBits(~bitcast<u32>(face.x));
  return vec4<f32>(tint.rgb, f32(bits) / 64.0);
}
