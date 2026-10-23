struct VOut {
  @builtin(position) clip : vec4<f32>,
  @location(0) color : vec4<f32>,
}

@group(0) @binding(0) var tex2d : texture_2d<f32>;
@group(0) @binding(1) var tex1d : texture_1d<f32>;
@group(0) @binding(2) var tex3d : texture_3d<f32>;
@group(0) @binding(3) var texCube : texture_cube<f32>;
@group(0) @binding(4) var texArray : texture_2d_array<f32>;
@group(0) @binding(5) var texMS : texture_multisampled_2d<f32>;
@group(0) @binding(6) var samp : sampler;
@group(0) @binding(7) var writeTex : texture_storage_2d<rgba8unorm, write>;
@group(1) @binding(0) var<uniform> params : mat4x4<f32>;
@group(1) @binding(1) var<storage, read_write> scratch : array<u32>;

@vertex
fn vs(@builtin(vertex_index) vi : u32) -> VOut {
  var out : VOut;
  let angle = f32(vi) * 0.33;
  let position = vec4<f32>(cos(angle), sin(angle), 0.0, 1.0);
  out.clip = params * position;
  out.color = vec4<f32>(position.xy, f32(vi % 4u) * 0.25, 1.0);
  return out;
}

@fragment
fn fs(@location(0) color : vec4<f32>) -> @location(0) vec4<f32> {
  let uv = color.xy;
  var sum = textureSample(tex2d, samp, uv);
  sum = sum + textureSample(tex1d, samp, uv.x);
  sum = sum + textureSample(tex3d, samp, vec3<f32>(uv, 0.5));
  sum = sum + textureSample(texCube, samp, normalize(vec3<f32>(uv, 1.0)));
  sum = sum + textureSample(texArray, samp, uv, u32(uv.x * 4.0) % 2u);
  let level = select(0u, 1u, uv.y > 0.5);
  sum = sum + textureLoad(tex2d, vec2<i32>(i32(uv.x * 31.0), i32(uv.y * 31.0)), level);
  sum = sum + textureLoad(texMS, vec2<i32>(1, 1), u32(uv.x * 3.9) % 4u);
  textureStore(writeTex, vec2<i32>(i32(uv.x * 31.0), i32(uv.y * 31.0)), sum);
  scratch[u32(uv.x * 31.0) % 16u] = bitcast<u32>(sum.r);
  return sum;
}

@compute @workgroup_size(1, 1, 1)
fn cs() {
  let dims = array<f32, 4>(
    f32(textureDimensions(tex2d).x),
    f32(textureDimensions(tex1d)),
    f32(textureDimensions(tex3d).x),
    f32(textureNumLayers(texArray)));
  var longest : f32 = 0.0;
  for (var i = 0u; i < 4u; i = i + 1u) {
    longest = max(longest, dims[i]);
  }
  scratch[0u] = bitcast<u32>(longest);
}

@compute @workgroup_size(4, 1, 1)
fn cs_levels(@builtin(local_invocation_id) lid : vec3<u32>) {
  let size = textureDimensions(tex2d, lid.x);
  let gather = textureGather(0u, tex2d, samp, vec2<f32>(0.25));
  scratch[lid.x] = bitcast<u32>(gather.x + f32(size.x) * 0.01);
}
