
var module;
var instance;
var heap;
var global_arguments = arguments;
var exit_status = 0;

function print_usage() {
    print('Usage: d8 --expose-wasm runtime.js -- <program.wasm> <program arg1> <program arg2> ...')
    quit(1); // TODO: this is d8 specific
}

function utf8encode(s) {
    return unescape(encodeURIComponent(s));
}

function utf8decode(s) {
    return decodeURIComponent(escape(s));
}

function fromString(string, pointer) {
    for (i = 0; i < string.length; i++) {
        heap[pointer + i] = string.charCodeAt(i);
    }
    heap[pointer + string.length] = 0;
}

function toString(pointer) {
    var string = '';
    for (var i = pointer; heap[i] != 0; i++) {
        string += String.fromCharCode(heap[i]);
    }
    return string;
}

var konan_dependencies = {
    env: {
        abort: function() {
            throw "abort()";
        },
        morecore_current_limit: function() {
            return instance.exports.memory.buffer.byteLength;
        },
        Konan_js_arg_size: function(index) {
            if (index >= global_arguments.length) return -1;
            return global_arguments[index].length + 1; // + 1 for trailing zero.
        },
        Konan_js_fetch_arg: function(index, ptr) {
            var arg = utf8encode(global_arguments[index]);
            fromString(arg, ptr)
        },
        pow: Math.pow, // This is for snprintf implementation.
        // TODO: Account for fd and size.
        write: function(fd, str, size) {
            if (fd != 1 && fd != 2) throw ("write(" + fd +", ...)")
            // TODO: There is no writeErr() in d8. 
            // Approximate it with write() to stdout for now.
            write(utf8decode(toString(str))); // TODO: write() d8 specific.
        }
    }
};

module = new WebAssembly.Module(new Uint8Array(readbuffer(arguments[0])));
module.env = {};
module.env.memoryBase = 0;
module.env.tablebase = 0;
module.env.memory = new WebAssembly.Memory({ initial: 256 });

instance = new WebAssembly.Instance(module, konan_dependencies);
heap = new Uint8Array(instance.exports.memory.buffer);

try {
  exit_status = instance.exports.Konan_js_main(arguments.length);
} catch (e) {
  print("Exception executing Konan_js_main: " + e);
  exit_status = 1;
}

quit(exit_status); // TODO: d8 specific.

