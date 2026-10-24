#   Domato - WGSL corpus parsing for the WebGPU grammar
#   ---------------------------------------------------
#
#   Written and maintained by Ivan Fratric <ifratric@google.com>
#   Modified by Brendon Tiszka to target webgpu <tiszka@google.com>
#
#   Copyright 2017 Google Inc. All Rights Reserved.
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import re


def extract_shader_stages_and_functions(code):
    # Pattern to match both single-line and multiline stage attributes without backtracking
    pattern = r'@(compute|vertex|fragment)(?:\s+@[a-zA-Z0-9_]+(?:\([^)]*\))?)*\s+fn\s+(\w+)'
    matches = re.finditer(pattern, code)

    # Extract stage-function pairs
    result = []
    for match in matches:
        stage_attr = '@' + match.group(1)
        function_name = match.group(2)
        result.append((stage_attr, function_name))

    return result


# Every wgsl module in the corpus exposes the same stage contract, so the fallback
# names double as the contract: a grammar symbol must always have a creator, even for
# a shader set that lacks that stage (domato-example.wgsl is compute-only).
_STAGES = {
    "@compute": ("<computeEntryPoint>", "cs"),
    "@vertex": ("<vertexEntryPoint>", "vs"),
    "@fragment": ("<fragmentEntryPoint>", "fs"),
}


def parse_entrypoints(shaders):
    by_stage = {attr: [] for attr in _STAGES}
    for shader in shaders:
        for attr, fn in extract_shader_stages_and_functions(shader):
            if fn not in by_stage[attr]:
                by_stage[attr].append(fn)

    result = ""
    for attr, (symbol, fallback) in _STAGES.items():
        for fn in by_stage[attr] or [fallback]:
            result += "{} = \"{}\"\n".format(symbol, fn)

    return result


def parse_stage_descriptors(shaders):
    """Paired module+entryPoint descriptors for the ten template modules.

    A grammar symbol cannot correlate two independent placeholders, so a rule
    that writes `<GPUShaderModule>` next to `<computeEntryPoint>` pairs a
    random module with a function name from a different one and the pipeline
    fails validation. These aggregates are defined once per (shader index,
    stage function), so every expansion names the module it was read from.
    ShaderN is declared by the template in the same order as this list.
    """
    result = ""
    render_found = False
    for index, shader in enumerate(shaders):
        stages = extract_shader_stages_and_functions(shader)
        vertex = next((fn for attr, fn in stages if attr == "@vertex"), None)
        fragment = next((fn for attr, fn in stages if attr == "@fragment"), None)
        for attr, fn in stages:
            if attr == "@compute":
                result += '<computeStage> = {{ module: Shader{}, entryPoint: "{}" }}\n'.format(index, fn)
                result += (
                    '<computePipelineDesc> = {{ layout: "auto", compute: {{ module: Shader{}, entryPoint: "{}" }} }}\n'.format(index, fn)
                )
            elif attr == "@vertex":
                result += (
                    '<vertexState> = {{ module: Shader{}, entryPoint: "{}", constants: {{}}, buffers: [] }}\n'.format(index, fn)
                )
            elif attr == "@fragment":
                result += (
                    '<fragmentState> = {{ module: Shader{}, entryPoint: "{}", constants: {{}}, targets: [{{ format: "rgba8unorm" }}] }}\n'.format(index, fn)
                )
        # This is the exact shape check_wgsl.py verifies against every corpus
        # module: one module for both stages, one rgba8unorm target, no vertex
        # buffers. Only the first function of each stage is used because that
        # is the pair the corpus was validated with.
        if vertex is not None and fragment is not None:
            render_found = True
            result += (
                '<renderPipelineDesc> = {{ layout: "auto", '
                'vertex: {{ module: Shader{index}, entryPoint: "{vertex}", constants: {{}}, buffers: [] }}, '
                'fragment: {{ module: Shader{index}, entryPoint: "{fragment}", constants: {{}}, targets: [{{ format: "rgba8unorm" }}] }} }}\n'
            ).format(index=index, vertex=vertex, fragment=fragment)
    # A sample of ten compute-only modules must not make the grammar
    # unresolvable: these descriptors validate as failures, not as parse errors.
    if not render_found:
        result += (
            '<renderPipelineDesc> = { layout: "auto", vertex: { module: Shader0, entryPoint: "vs", buffers: [] }, '
            'fragment: { module: Shader0, entryPoint: "fs", targets: [{ format: "rgba8unorm" }] } }\n'
        )
    if '<computeStage>' not in result:
        result += '<computeStage> = { module: Shader0, entryPoint: "cs" }\n'
        result += '<computePipelineDesc> = { layout: "auto", compute: { module: Shader0, entryPoint: "cs" } }\n'
    return result


def parse_bindings(shaders):
    binding_pattern = r'@binding\((\d+)\)'

    binding_numbers = []
    for shader in shaders:
        matches = re.finditer(binding_pattern, shader)
        binding_numbers.extend(match.group(1) for match in matches)

    return "\n".join(f"<BindInt> = {binding}" for binding in binding_numbers)
