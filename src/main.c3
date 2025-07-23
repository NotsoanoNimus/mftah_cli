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
const DEFAULT_MEMORY_LIMIT_MIB = 2048;   // 2,048 MiB (or 2 GiB)
const FIXED_OFFSET_LIMIT = 256 * 1024 * 1024;   // 256 MiB

struct AlgorithmOption
{
    String name;
    MftahCryptoType type;
}
const AlgorithmOption[] ALGORITHM_OPTIONS = {
    { "chacha20", CHACHA20_POLY1305 },
    { "aes256cbc", AES_256_CBC_HMAC_SHA256 },
};


faultdef DIE;

macro void? @die(msg, args...)
{
    io::eprintf("FATAL:  ");
    io::eprintf(msg, ...args);
    io::eprintn("");

    (void)io::stdout().flush();
    (void)io::stderr().flush();

    return DIE?;
}

macro @usage()
{
    io::printf($embed("usage.txt"), DEFAULT_STREAM_BLOCK_FACTOR, DEFAULT_THREADS, mftah::MAX_THREAD_COUNT, DEFAULT_MEMORY_LIMIT_MIB);
    (void)io::stdout().flush();
    os::exit(1);
}

macro @version_info()
{
    // TODO!
    io::printf("VERSION INFO\n");
    (void)io::stdout().flush();
    os::exit(1);
}

macro @verbose(msg, args...)
{
    if (!options.verbose) return;
    io::printf("VERBOSE:  ");
    io::printf(msg, ...args);
    io::printn("");
}

macro @info(msg, args...)
{
    if (options.quiet) return;
    // io::printf("INFO:  ");
    io::printf(msg, ...args);
    io::printn("");
}


enum CliOperation : const char
{
    ENCRYPT = 1,
    DECRYPT,
    QUERY
}

struct CliOptions
{
    bool noninteractive;
    bool quiet;
    bool verbose;

    bool stream;
    bool force_key;

    char stream_factor;
    char threads;
    ulong fixed_offset;
    MftahCryptoType intended_type;

    usz memory_limit_mib;

    CliOperation operation;

    String output_path;
    File output_file;
    String input_path;
    File input_file;

    String keyfile_path;
    String key;

    char[] loaded_key;
}
CliOptions options;

fn void? process_options(String[] args)
{
    bool is_query, is_encrypt, is_decrypt, needs_help, wants_version;
    String algorithm = "chacha20";

    if (catch opt::@parse(
        args,
        "h", "help", &needs_help,
        "q", "query", &is_query,
        "e", "encrypt", &is_encrypt,
        "d", "decrypt", &is_decrypt,
        "s", "stream", &options.stream,
        "", "stream-factor", &options.stream_factor,
        "o", "output", &options.output_path,
        "i", "input", &options.input_path,
        "k", "key", &options.key,
        "K", "keyfile", &options.keyfile_path,
        "t", "threads", &options.threads,
        "", "fixed-offset", &options.fixed_offset,
        "a", "algorithm", &algorithm,
        "F", "force-key", &options.force_key,
        "n", "noninteractive", &options.noninteractive,
        "l", "limit", &options.memory_limit_mib,
        "", "version", &wants_version,
        "Q", "quiet", &options.quiet,
        "v", "verbose", &options.verbose,
    )) @usage();

    if (args.len < 2 || needs_help) @usage();

    if (wants_version) @version_info();

    if (options.verbose && options.quiet) @die("I can't be quiet AND verbose simultaneously! What do you want from me?! :(")!;

    if (options.verbose) @verbose("Operating in verbose mode ^_^");

    if ((char)is_query + (char)is_encrypt + (char)is_decrypt > 1)
    {
        @die("You can only choose one operation: query (-q), encrypt (-e), or decrypt (-d).")!;
    }

    switch
    {
        case is_encrypt: options.operation = ENCRYPT;
        case is_decrypt: options.operation = DECRYPT;
        case is_query: options.operation = QUERY;

        default: @die("You must supply at least one operation: query (-q), encrypt (-e), or decrypt (-d).")!;
    }

    // Set defaults.
    if (!options.memory_limit_mib) options.memory_limit_mib = DEFAULT_MEMORY_LIMIT_MIB;
    if (!options.threads) options.threads = DEFAULT_THREADS;
    if (!options.stream_factor) options.stream_factor = DEFAULT_STREAM_BLOCK_FACTOR;

    // Begin generic checks.
    if (is_encrypt && (options.threads > mftah::MAX_THREAD_COUNT || options.threads < 1))
    {
        @die("Invalid thread count; limits are %d and %d, inclusive.", 1, mftah::MAX_THREAD_COUNT)!;
    }
    if (is_encrypt && options.stream && (options.stream_factor < mftah::MIN_STREAM_BLOCK_SIZE_FACTOR || options.stream_factor > mftah::MAX_STREAM_BLOCK_SIZE_FACTOR))
    {
        @die("Invalid stream factor size; limits are %d and %d, inclusive.", mftah::MIN_STREAM_BLOCK_SIZE_FACTOR, mftah::MAX_STREAM_BLOCK_SIZE_FACTOR)!;
    }

    if (!options.key.len && !options.keyfile_path.len) @die("No key (-k) or keyfile (-K) was specified.")!;
    if (options.key.len && options.keyfile_path.len) @die("Both a key (-k) AND a keyfile (-K) cannot be specified; choose only one.")!;

    if (!options.input_path) options.input_file = *io::stdin();
    if (!options.output_path) options.output_file = *io::stdout();

    // Options are largely regarded/selected based on the chosen mode.
    switch (options.operation)
    {
        case ENCRYPT:
            if GET_ALGO: (true)
            {
                // $foreach $subarr : ALGORITHM_OPTIONS :
                $for var $i = 0; $i < ALGORITHM_OPTIONS.len; ++$i :
                    if (algorithm == ALGORITHM_OPTIONS[$i].name)
                    {
                        options.intended_type = ALGORITHM_OPTIONS[$i].type;
                        break GET_ALGO;
                    }
                $endfor

                // Code reaching this statement behaves as a 'default' case for algorithm selection.
                io::eprintn("Invalid algorithm. Valid algorithm names are:");
                // $foreach $subarr : ALGORITHM_OPTIONS :
                $for var $i = 0; $i < ALGORITHM_OPTIONS.len; ++$i :
                    io::eprintf("    * %s\n", ALGORITHM_OPTIONS[$i].name);
                $endfor

                @die("Please specify a valid algorithm.")!;
            }

        case DECRYPT: return;

        case QUERY: return;
    }
}


// NOTE: This specifically loads the key directly into the static 'options' variable,
//   because we don't want stack or other temp memory locations to hold our key. While
//   none of that is a guarantee, it's cozy to minimize it anyway.
fn void? load_key()
{
    if (options.keyfile_path.len)
    {
        @info("Loading input key from a file path...");

        defer wipe_mem(options.keyfile_path, false);

        if (!file::exists(options.keyfile_path)) @die("Key file path '%s' does not exist or is not valid.", options.keyfile_path)!;

        File? f = file::open(options.keyfile_path, "r");
        if (catch oops = f) @die("Failed to open key file '%s' for reading with error '%s'.", options.keyfile_path, oops)!;
        if (catch oops = f.seek(0)) @die("Failed to seek key file '%s' with error '%s'.", options.keyfile_path, oops)!;

        defer (void)f.close();

        char[256] buff;
        defer mem::zero_volatile(&buff);

        usz max_size = 16 * 1024 * 1024;   // 16 MiB (absurd tbh)
        usz counter;

        options.loaded_key = mem::new_array(char, max_size)[:max_size];
        if (null == options.loaded_key.ptr) @die("Out of memory when creating ")!;

        while (true)
        {
            if (counter > (max_size - buff.len)) @die("Out of memory: key files are limited to 16 MiB in size.")!;

            usz? read = f.read(buff[..]);
            if (catch oops = read) return @die("Failed to read key file with error '%s'.", oops)!;

            if (0 == read) break;

            options.loaded_key[counter:read] = buff[:read];

            counter += read;
        }

        options.loaded_key = options.loaded_key[:counter];   // trim to actual length

        @verbose("Key file: loaded and readied %d bytes.", counter);
    }
    else
    {
        @info("Loading input key directly from parameters...");

        defer wipe_mem(options.key, false);

        options.loaded_key = mem::new_array(char, options.key.len)[:options.key.len];
        options.loaded_key[..] = options.key[..];   // memcpy

        @verbose("Key: loaded and readied %d bytes.", options.key.len);
    }
}


fn void wipe_mem(char[] target, bool frees = true)
{
    if (!target.len) return;

    // Pass over the key several times with varying bit patterns. This is overkill, but the fun kind.
    $for var $x = 0; $x < 7; ++$x:
        mem::set(target.ptr, 0x5A, target.len);
        mem::set(target.ptr, 0xA5, target.len);
        mem::set(target.ptr, 0xFF, target.len);
        mem::set(target.ptr, 0x00, target.len);
    $endfor

    if (frees) mem::free(target.ptr);
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
    load_key()!;
    defer wipe_mem(options.loaded_key);

    switch (options.operation)
    {
        case ENCRYPT:
            if (options.stream)
            {
                if (catch oops = mftah::stream_new(options.loaded_key, options.intended_type, options.stream_factor, &read_next_input_block, &yield_next_output_block))
                {
                    // Need to remove any potential output that has been yielded to a file. No need to securely erase it though.

                    @die("Captured fault '%s' when attempting to create a streamed MFTAH file.", oops)!;
                }
            }
            else
            {
                char[] payload = consume_input();
                defer wipe_mem(payload);

                char[]? encrypted = mftah::new(payload, options.loaded_key, options.intended_type, options.threads, options.fixed_offset);

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
            }
            else
            {
                char[] payload = consume_input();   // NOTE: no need for secure wipe of encrypted input buffer

                char[]? decrypted = mftah::decrypt(payload, options.loaded_key);
                
                if (catch oops = decrypted)
                {
                    (void)@die("Captured fault '%s' when attempting to decrypt input MFTAH payload.", oops);

                    return oops?;
                }
            }

        case QUERY:
            io::printn("TODO! PAYLOAD INFO");
    }

    return 0;
}
