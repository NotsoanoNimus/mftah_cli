module mftah_cli;

import mftah;
import opt;

import std::thread;
import std::os;
import std::io;

import libc;


const DEFAULT_THREADS = 8;
const DEFAULT_STREAM_BLOCK_FACTOR = 8;
const DEFAULT_CRYPTO_TYPE = MftahCryptoType.CHACHA20_POLY1305;
const FIXED_OFFSET_LIMIT = 256 * 1024 * 1024;   // 256 MiB


// Scoped at the global level to allow stream hooks to switch behavior if true.
bool rekey_canary = false;


faultdef DIE;

macro void? @die(msg, args...)
{
    io::eprintf(msg, ...args);
    io::eprintn("");

    return DIE?;
}

const char[] USAGE_TEXT = $embed("usage.txt");

macro @usage()
{
    io::printf(USAGE_TEXT, DEFAULT_THREADS, mftah::MAX_THREAD_COUNT);
    os::exit(1);
}

macro @version_info()
{
    // TODO!
    io::printf("VERSION INFO\n");
    os::exit(1);
}


enum CliOperation : const char
{
    ENCRYPT = 1,
    DECRYPT,
    REKEY,
    QUERY
}

struct CliOptions
{
    bool stream;
    bool force_key;
    bool noninteractive;

    char stream_factor;
    char threads;
    ulong fixed_offset;
    MftahCryptoType intended_type;

    CliOperation operation;

    String output_path;
    File output_file;
    String input_path;
    File input_file;

    String keyfile_path;
    String key;

    String new_keyfile_path;
    String new_key;

    char[] loaded_key;
    char[] new_loaded_key;
}
CliOptions options;

fn void? process_options(String[] args)
{
    bool is_query, is_encrypt, is_decrypt, is_rekey, needs_help, wants_version;
    String algorithm = "chacha20";

    options.stream_factor = DEFAULT_STREAM_BLOCK_FACTOR;
    options.threads = DEFAULT_THREADS;

    if (catch opt::@parse(
        args,
        "h", "help", &needs_help,
        "q", "query", &is_query,
        "e", "encrypt", &is_encrypt,
        "d", "decrypt", &is_decrypt,
        "r", "rekey", &is_rekey,
        "s", "stream", &options.stream,
        "", "stream-factor", &options.stream_factor,
        "o", "output", &options.output_path,
        "i", "input", &options.input_path,
        "k", "key", &options.key,
        "K", "keyfile", &options.keyfile_path,
        "c", "change-key", &options.new_key,
        "C", "change-keyfile", &options.new_keyfile_path,
        "t", "threads", &options.threads,
        "", "fixed-offset", &options.fixed_offset,
        "a", "algorithm", &algorithm,
        "F", "force-key", &options.force_key,
        "n", "noninteractive", &options.noninteractive,
        "v", "version", &wants_version,
    )) @usage();

    if (needs_help) @usage();

    if (wants_version) @version_info();

    if ((char)is_query + (char)is_encrypt + (char)is_decrypt + (char)is_rekey > 1)
    {
        @die("You can only choose one operation: query (-q), encrypt (-e), decrypt (-d), or rekey (-r).")!;
    }

    switch
    {
        case is_encrypt: options.operation = ENCRYPT;
        case is_decrypt: options.operation = DECRYPT;
        case is_rekey: options.operation = REKEY;
        case is_query: options.operation = QUERY;

        default: @die("You must supply at least one operation: query (-q), encrypt (-e), decrypt (-d), or rekey (-r).")!;
    }

    if (!options.key.len && !options.keyfile_path.len) @die("No key (-k) or keyfile (-K) was specified.")!;
    if (options.key.len && options.keyfile_path.len) @die("Both a key (-k) AND a keyfile (-K) cannot be specified; choose only one.")!;

    // Options are largely regarded/selected based on the chosen mode.
    switch (options.operation)
    {
        // case ENCRYPT:

        // case DECRYPT:

        // case REKEY:

        // case QUERY:
    }
}


// NOTE: This specifically loads the key directly into the static 'options' variable,
//   because we don't want stack or other temp memory locations to hold our key. While
//   none of that is a guarantee, it's cozy to minimize it anyway.
fn void load_keys()
{
    //
}


fn void wipe_mem(char[] target)
{
    if (!target.len) return;

    // Pass over the key several times with varying bit patterns. This is overkill, but the fun kind.
    $for var $x = 0; $x < 7; ++$x:
        mem::set(target.ptr, 0x5A, target.len);
        mem::set(target.ptr, 0xA5, target.len);
        mem::set(target.ptr, 0xFF, target.len);
        mem::set(target.ptr, 0x00, target.len);
    $endfor

    mem::free(target.ptr);
    target = {};
}


fn char[] consume_input()
{
    return {};
}


fn void flush_output(char[] data)
{
    //
}


fn char[] read_next_input_block(usz requested_size)
{
    return {};
}


fn void yield_next_output_block(char[] data)
{
    //
}


fn int main(String[] args) => main_inner(args) ?? 1;

fn int? main_inner(String[] args)
{
    process_options(args)!;

    // Load all password/key variables.
    load_keys();
    defer wipe_mem(options.loaded_key);
    defer wipe_mem(options.new_loaded_key);

    bool working = true;
    char[] payload;   // scoped here so REKEY can fill it with 'decrypt' data

    switch (options.operation)
    {
        case ENCRYPT:
            char[] enc_key = !rekey_canary ? options.loaded_key : options.new_loaded_key;

            if (options.stream)
            {
                if (catch oops = mftah::stream_new(enc_key, options.intended_type, options.stream_factor, &read_next_input_block, &yield_next_output_block))
                {
                    // Need to remove any potential output that has been yielded to a file. No need to securely erase it though.

                    @die("Captured fault '%s' when attempting to create a streamed MFTAH file.", oops)!;
                }
            }
            else
            {
                if (!payload.len) payload = consume_input();
                defer wipe_mem(payload);

                char[]? encrypted = mftah::new(payload, enc_key, options.intended_type, options.threads, options.fixed_offset);

                if (catch oops = encrypted)
                {
                    (void)@die("Captured fault '%s' when attempting to create a fixed-length MFTAH file.", oops);

                    return oops?;
                }

                flush_output(encrypted);
            }

        case DECRYPT:
            if (options.stream)
            {
                if (catch oops = mftah::stream_decrypt(options.loaded_key, &read_next_input_block, &yield_next_output_block))
                {
                    // Need to shred any output that may have been yielded so far. If this output was going to STDOUT, there's not really anything we can do.
                    // try_shred_output();

                    @die("Captured fault '%s' when attempting to decrypt a streamed MFTAH file.", oops)!;
                }

                // NOTE: Options specify that when STDOUT is the output, streaming mode cannot be used to rekey since decrypted output can't be buffered.
                //   An alternative is to just call the program in an decrypt-then-encrypt pipeline.
                if (rekey_canary)
                {
                    @swap(options.input_path, options.output_path);   // write back re-encrypted data to the file we read in, from the file we wrote out

                    @swap(options.input_file, options.output_file);
                }
            }
            else
            {
                if (!payload.len) payload = consume_input();

                char[]? decrypted = mftah::decrypt(payload, options.loaded_key);
                
                if (catch oops = decrypted)
                {
                    (void)@die("Captured fault '%s' when attempting to decrypt input MFTAH payload.", oops);

                    return oops?;
                }

                // When rekeying, do not flush the decrypted output; instead, keep it in-memory and proceed to ENCRYPT with the new key.
                if (!rekey_canary)
                {
                    flush_output(decrypted);
                }
                else
                {
                    payload = decrypted;
                }
            }

            if (rekey_canary) nextcase ENCRYPT;

        case REKEY:
            rekey_canary = true;
            nextcase DECRYPT;

        case QUERY:
            io::printn("TODO! PAYLOAD INFO");
    }

    return 0;
}
