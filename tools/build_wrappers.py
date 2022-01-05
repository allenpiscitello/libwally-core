#!/usr/bin/env python3
import os
import subprocess

# Structs with no definition in the public header files
OPAQUE_STRUCTS = [u'words']


def replace_text(filename, text, delims):
    lines = [line.rstrip() for line in open(filename)]
    start, end = lines.index(delims[0]), lines.index(delims[1])
    replaced = lines[:start + 1] + text + lines[end:]
    replaced = [l + u'\n' for l in replaced]
    open(filename, u'w').writelines([l for l in replaced])


def get_non_elements_functions():
    cmd = "-E include/*.h | sort | uniq | grep '^ *int ' | grep '(' | sed -e 's/^ *int //g' -e 's/(.*//g' | egrep '^wally_|^bip'"
    try:
        funcs = subprocess.check_output(u'gcc ' + cmd, shell=True)
    except subprocess.CalledProcessError:
        funcs = subprocess.check_output(u'clang ' + cmd, shell=True)
    return funcs.decode('utf-8').split(u'\n')


class Arg(object):
    def __init__(self, definition):
        if u'*' in definition:
            self.is_pointer = True
            self.is_pointer_pointer = u'**' in definition
            if self.is_pointer_pointer:
                self.type = definition.split(' **')[0] + '**'
            else:
                self.type = definition.split(' *')[0] + '*'
            self.name = definition[len(self.type) + 1:]
            self.is_struct = u'struct' in self.type
            if self.is_struct:
                self.struct_name = self.type.split(u' ')[-1].split(u'*')[0]
                self.is_opaque = self.struct_name in OPAQUE_STRUCTS
        else:
            self.is_pointer = False
            self.is_pointer_pointer = False
            self.is_struct = False
            self.type, self.name = definition.split(' ')
        self.is_const = self.type.startswith(u'const ')


class Func(object):
    def __init__(self, definition, non_elements):
        # Strip return type and closing ')', extract name
        self.name, definition = definition[4:-1].split(u'(')
        # Parse arguments
        self.args = [Arg(d) for d in definition.split(u', ')]
        self.is_elements = self.name not in non_elements


def is_array(func, arg, n, num_args, types):
    return arg.type in types and n != num_args -1 and \
               func.args[n + 1].type == u'size_t' and \
               func.args[n + 1].name.endswith(u'len')


def is_buffer(func, arg, n, num_args):
    return is_array(func, arg, n, num_args, [u'const unsigned char*', u'unsigned char*'])


def is_int_buffer(func, arg, n, num_args):
    return is_array(func, arg, n, num_args, [u'const uint32_t*', u'const uint64_t*'])


def gen_python_cffi(funcs):
    typemap = {
        u'int'           : u'c_int',
        u'size_t*'       : u'c_ulong_p',
        u'size_t'        : u'c_ulong',
        u'uint32_t*'     : u'c_uint_p',
        u'uint32_t'      : u'c_uint',
        u'uint64_t*'     : u'c_uint64_p',
        u'uint64_t'      : u'c_uint64',
        u'void**'        : u'POINTER(c_void_p)',
        u'void*'         : u'c_void_p',
        u'unsigned char*': u'c_void_p',
        u'char**'        : u'c_char_p_p',
        u'char*'         : u'c_char_p',
        u'uint8_t'       : u'c_uint8'
        }
    def map_arg(arg, n, num_args):
        argtype = arg.type[6:] if arg.is_const else arg.type # Strip const
        if argtype == u'uint64_t*' and n != num_args - 1:
            return u'POINTER(c_uint64)'
        if argtype in typemap:
            return typemap[argtype]
        if arg.is_struct:
            if arg.is_opaque:
                return typemap[u'void**' if arg.is_pointer_pointer else u'void*']
            text = f'POINTER({arg.struct_name})'
            if arg.is_pointer_pointer:
                text = f'POINTER({text})'
            return text
        assert False, f'ERROR: Unknown argument type "{argtype}"'

    cffi = []
    for func in funcs:
        num_args = len(func.args)
        mapped = u', '.join([map_arg(arg, i, num_args) for i, arg in enumerate(func.args)])
        cffi.append(f"    ('{func.name}', c_int, [{mapped}]),")

    cffi.sort()
    replace_text(u'src/test/util.py', cffi,
                 [u'    # BEGIN AUTOGENERATED', u'    # END AUTOGENERATED'])


def gen_python_swig(funcs):
    def map_arg(func, arg, n, num_args):
        if is_buffer(func, arg, n, num_args):
            macro = u'output' if arg.type == u'unsigned char*' else u'nullable'
            return f'%pybuffer_{macro}_binary({arg.type} {arg.name}, size_t {func.args[n + 1].name});'
        return u''

    swig = []
    for func in funcs:
        num_args = len(func.args)
        mapped = [map_arg(func, arg, i, num_args) for i, arg in enumerate(func.args)]
        swig.extend([m for m in mapped if m])

    swig = sorted(set(swig))
    replace_text(u'src/swig_python/swig.i', swig,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_java_swig(funcs):
    def map_arg(func, arg, n, num_args):
        if arg.type in [u'const unsigned char*', u'unsigned char*'] and \
                n != num_args -1 and func.args[n + 1].type == u'size_t' and \
                func.args[n + 1].name.endswith(u'len'):
            return f'%apply(char *STRING, size_t LENGTH) {{ ({arg.type} {arg.name}, size_t {func.args[n + 1].name}) }};'
        return u''

    swig = []
    for func in funcs:
        num_args = len(func.args)
        mapped = [map_arg(func, arg, i, num_args) for i, arg in enumerate(func.args)]
        swig.extend([m for m in mapped if m])

    swig = sorted(set(swig))
    replace_text(u'src/swig_java/swig.i', swig,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_wally_hpp(funcs):
    cpp, cpp_elements = {}, {}
    for func in funcs:
        num_args = len(func.args)
        vardecl = ''
        t_types, cpp_args, call_args = [], [], []
        skip = False
        for n, arg in enumerate(func.args):
            if skip:
                skip = False
                continue
            if is_buffer(func, arg, n, num_args) or is_int_buffer(func, arg, n, num_args):
                t_types.append(f'class {arg.name.upper()}')
                const = u'const ' if arg.is_const else ''
                cpp_args.append(f'{const}{arg.name.upper()}& {arg.name}')
                call_args.extend([f'{arg.name}.data()', f'{arg.name}.size()'])
                skip = True
            elif arg.type == u'size_t*' and arg.name == u'written' and \
                    n >= 2 and is_buffer(func, func.args[n-2], n-2, num_args):
                vardecl = u'    size_t n;'
                cpp_args.append(f'{arg.type} {arg.name} = 0')
                call_args.append(f'{arg.name} ? {arg.name} : &n')
            elif arg.type in [u'int', u'size_t', u'uint32_t', u'uint64_t',
                              u'int*', u'size_t*', u'uint32_t*', u'uint64_t*']:
                cpp_args.append(f'{arg.type} {arg.name}')
                call_args.append(f'{arg.name}')
            elif arg.is_pointer:
                if arg.is_pointer_pointer or n == num_args - 1:
                    cpp_args.append(f'{arg.type} {arg.name}')
                    call_args.append(f'{arg.name}')
                else:
                    t_types.append(f'class {arg.name.upper()}')
                    cpp_args.append(f'const {arg.name.upper()}& {arg.name}')
                    call_args.append(f'detail::get_p({arg.name})')

        impl = []
        if len(t_types):
            impl.append(f'template <{", ".join(t_types)}>')
        func_name = func.name[6:] if func.name.startswith(u'wally_') else func.name
        impl.append(f'inline int {func_name}({", ".join(cpp_args)}) {{')
        if vardecl:
            impl.append(vardecl)
        impl.append(f'    int ret = ::{func.name}({", ".join(call_args)});')
        if vardecl:
            prev = func.args[-3]
            impl.append(f'    return written || ret != WALLY_OK ? ret : n == static_cast<size_t>({prev.name}.size()) ? WALLY_OK : WALLY_EINVAL;')
        else:
            impl.append(f'    return ret;')
        impl.extend([u'}', u''])
        # FIXME: sort
        (cpp_elements if func.is_elements else cpp)[func.name] = impl

    text = []
    for f in sorted(cpp.keys()):
        text.extend(cpp[f])
    text.append(u'#ifdef BUILD_ELEMENTS')
    for f in sorted(cpp_elements.keys()):
        text.extend(cpp_elements[f])
    text[-1] = u'#endif // BUILD_ELEMENTS'
    replace_text(u'include/wally.hpp', text,
                 [u'/* BEGIN AUTOGENERATED */', u'/* END AUTOGENERATED */'])


def gen_wasm_exports(funcs):
    exports = ','.join([f"'_{func.name}'" for func in funcs if not func.is_elements])
    elements_exports = ','.join([f"'_{func.name}'" for func in funcs if func.is_elements])

    text = [
        f"EXPORTED_FUNCTIONS=\"['_malloc','_free',{exports}\"",
        'if [ -n "$ENABLE_ELEMENTS" ]; then',
        f'    EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS"",{elements_exports}"',
        'fi',
        'EXPORTED_FUNCTIONS="$EXPORTED_FUNCTIONS""]"'
    ]
    replace_text(u'tools/wasm_exports.sh', text,
                 [u'# BEGIN AUTOGENERATED', u'# END AUTOGENERATED'])


if __name__ == "__main__":

    non_elements = get_non_elements_functions()

     # Call sphinx to dump our definitions
    envs = {k:v for k,v in os.environ.items()}
    envs[u'WALLY_DOC_DUMP_FUNCS'] = u'1'
    cmd = ['sphinx-build', '-b', 'html', '-a', '-c', 'docs/source', 'docs/source', 'docs/build/html']
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=envs)

    # Process the lines into func objects for each function
    funcs = process.stdout.decode('utf-8').split(u'\n')
    funcs = [Func(f, non_elements) for f in funcs if f.startswith(u'int ')]

    # Generate the wrapper code
    gen_python_cffi(funcs)
    gen_python_swig(funcs)
    gen_java_swig(funcs)
    gen_wally_hpp(funcs)
    gen_wasm_exports(funcs)
