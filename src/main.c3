module mftah_cli;

import mftah;
import opt;

import std::thread;
import std::os;
import std::io;
import std::math;

import libc;


const DEFAULT_THREADS = 8;
const DEFAULT_STREAM_BLOCK_FACTOR = 8;
const DEFAULT_MEMORY_LIMIT_MIB = 2048;   // 2,048 MiB (or 2 GiB)
const FIXED_OFFSET_LIMIT = 256 * 1024 * 1024;   // 256 MiB

struct AlgorithmOption
{
    String name;
    MftahCryptoType type;
}
const AlgorithmOption[] ALGORITHM_OPTIONS = {
    { "chacha20", CHACHA20_POLY1305 },   // default
    { "aes256cbc", AES_256_CBC_HMAC_SHA256 },
};


faultdef DIE;

macro void? @die(msg, args...)
{
    io::eprintf("FATAL:  ");
    io::eprintfn(msg, ...args);

    (void)io::stdout().flush();
    (void)io::stderr().flush();

    return DIE?;
}

macro @usage() @noreturn
{
    io::eprintf($embed("usage.txt"),
        DEFAULT_STREAM_BLOCK_FACTOR, DEFAULT_THREADS, mftah::MAX_THREAD_COUNT,
        FIXED_OFFSET_LIMIT / 1024 / 1024, FIXED_OFFSET_LIMIT, DEFAULT_MEMORY_LIMIT_MIB);
    (void)io::stderr().flush();
    os::exit(1);
}

macro @version_info() @noreturn
{
    // TODO!
    io::eprintfn("VERSION INFO");
    (void)io::stderr().flush();
    os::exit(1);
}

macro @verbose(msg, args...)
{
    if (!options.verbose) return;
    io::eprintf("VERBOSE:  ");
    io::eprintfn(msg, ...args);
}

macro @info(msg, args...)
{
    if (options.quiet) return;
    io::eprintfn(msg, ...args);
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

    bool uses_stdin;
    bool uses_stdout;

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
        "F", "force-key", &options.force_key,
        "t", "threads", &options.threads,
        "", "fixed-offset", &options.fixed_offset,
        "a", "algorithm", &algorithm,
        "n", "noninteractive", &options.noninteractive,
        "l", "limit", &options.memory_limit_mib,
        "Q", "quiet", &options.quiet,
        "v", "verbose", &options.verbose,
        "", "version", &wants_version,
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
    if (!options.threads) options.threads = DEFAULT_THREADS;
    if (!options.stream_factor) options.stream_factor = DEFAULT_STREAM_BLOCK_FACTOR;
    if (!options.memory_limit_mib) options.memory_limit_mib = DEFAULT_MEMORY_LIMIT_MIB;

    if (!options.key.len && !options.keyfile_path.len) @die("No key (-k) or keyfile (-K) was specified.")!;
    if (options.key.len && options.keyfile_path.len) @die("Both a key (-k) AND a keyfile (-K) cannot be specified; choose only one.")!;

    File? f;   // TODO: fix
    if (!options.input_path)
    {
        @info("Input: defaulting to the standard input (STDIN) stream.");

        if (options.stream) @info("WARNING:  Reading large amounts of data from STDIN without using 'stream' mode is cumbersome and slow.\n\tConsider using the '-s' option for this instead. Proceeding...");

        options.input_file = *io::stdin();
        options.uses_stdin = true;
    }
    else
    {
        if (!file::exists(options.input_path))
        {
            @die("The input file '%s' does not exist.", options.input_path)!;
        }
        f = file::open(options.input_path, "r");
        if (catch oops = f) //(f = file::open(options.input_path, "r")))
        {
            return @die("Failed to open input file (reason: %s).", oops);
        }
        options.input_file = f;
    }

    if (!is_query)
    {
        if (!options.output_path)
        {
            @info("Output: defaulting to the standard output (STDOUT) stream.");
            options.output_file = *io::stdout();
            options.uses_stdout = true;
        }
        else
        {
            if (file::exists(options.output_path) && !options.noninteractive)
            {
                @die("The output file '%s' already exists. To overwrite it, use the '-n' or '--noninteractive' option.", options.output_path)!;
            }
            f = file::open(options.output_path, "w");
            if (catch oops = f)
            {
                return @die("Failed to open output file (reason: %s).", oops)!;
            }
            options.output_file = f;
        }
    }

    // Options are largely regarded/selected based on the chosen mode.
    switch (options.operation)
    {
        case ENCRYPT:
            if (!options.stream)
            {
                if (options.threads > mftah::MAX_THREAD_COUNT || options.threads < 1)
                {
                    @die("Invalid thread count; limits are %d and %d, inclusive.", 1, mftah::MAX_THREAD_COUNT)!;
                }
                if (options.fixed_offset > FIXED_OFFSET_LIMIT)
                {
                    @die("The value '%d' is over the fixed offset limit of %d bytes.", options.fixed_offset, FIXED_OFFSET_LIMIT)!;
                }
            }
            else
            {
                if (options.stream_factor < mftah::MIN_STREAM_BLOCK_SIZE_FACTOR || options.stream_factor > mftah::MAX_STREAM_BLOCK_SIZE_FACTOR)
                {
                    @die("Invalid stream factor size; limits are %d and %d, inclusive.", mftah::MIN_STREAM_BLOCK_SIZE_FACTOR, mftah::MAX_STREAM_BLOCK_SIZE_FACTOR)!;
                }
            }
            if GET_ALGO: (true)
            {
                $for var $i = 0; $i < ALGORITHM_OPTIONS.len; ++$i :
                    if (algorithm == ALGORITHM_OPTIONS[$i].name)
                    {
                        options.intended_type = ALGORITHM_OPTIONS[$i].type;
                        break GET_ALGO;
                    }
                $endfor

                // Code reaching this statement behaves as a 'default' case for algorithm selection.
                io::eprintfn("\n\nInvalid algorithm '%s'. Valid algorithm names are:", algorithm);
                $for var $i = 0; $i < ALGORITHM_OPTIONS.len; ++$i :
                    io::eprintfn("    * %s", ALGORITHM_OPTIONS[$i].name);
                $endfor
                io::eprintn("");

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
    @verbose("wipe_mem: %p - %d - %s", target.ptr, target.len, frees);

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


fn char[]? consume_input()
{
    usz counter;
    usz load_chunk_size = 1024 * 1024;   // 1 MiB at a time
    usz memory_limit_bytes = options.memory_limit_mib * 1024 * 1024;

    @info("Reading input buffer...");

    usz buffer_size = options.uses_stdin ? load_chunk_size : file::get_size(options.input_path)!;
    if (!buffer_size) @die("Input file is empty or does not exist; cannot work with an empty buffer.")!;

    if (buffer_size > memory_limit_bytes)
    {
        @die("The input file size (%d bytes) is larger than the memory limit of %d MiB (%d bytes).\n\tUse the '-l' or '--limit' option to adjust this memory limit.",
            buffer_size, options.memory_limit_mib, memory_limit_bytes)!;
    }

    char[] buffer = mem::alloc_array(char, buffer_size)[:buffer_size];
    if (null == buffer.ptr) @die("Out of resources when allocating input buffer.")!;

    if (options.uses_stdin)
    {
        @verbose("Reading stream from STDIN (%s).", options.input_file);
        usz allocation_size = buffer_size;

        for (usz nbytes = 0; (nbytes = options.input_file.read(buffer[counter:buffer_size])!) > 0; counter += nbytes)
        {
            @verbose("-- Captured %d bytes.", nbytes);

            if (counter + buffer_size < allocation_size) continue;

            if (allocation_size == memory_limit_bytes)
            {
                @die("Out of memory: limit of %d MiB for dynamic STDIN buffering has been reached and will not be exceeded.\n\tUse the '-l' or '--limit' option to adjust this memory limit.", options.memory_limit_mib)!;
            }

            allocation_size = min(allocation_size * 2, memory_limit_bytes);   // double the buffer size each time to reduce realloc costs

            @verbose("Growing buffer...");
            buffer = mem::realloc(buffer, allocation_size)[:allocation_size];

            if (null == buffer.ptr) @die("Out of resources when reallocating the input buffer.")!;
            @verbose("Reallocated to %d bytes.", allocation_size);
        }

        @verbose("Successfully read %d bytes from the input (buffer size %d bytes).", counter, allocation_size);
    }
    else
    {
        @verbose("Consuming input wholesale from file (%d bytes)...", buffer_size);
        counter = options.input_file.read(buffer[:buffer_size])!;

        if (counter != buffer_size) @die("Expected to read %d bytes, but only got %d bytes.", buffer_size, counter)!;
    }

    return buffer[:counter];
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

fn void? try_shred_file(String path)
{
    if (!path.len) return;

    @info("Shredding %s...", path);

    @verbose("Getting file shred size.");
    usz file_size = file::get_size(path) ?? 0;

    @verbose("Got: %d", file_size);
    if (!file_size) return;

    defer
    {
        @verbose("Unlinking shredded file.");
        (void)file::delete(path);
    }

    @verbose("Opening output file in binary-append mode.");
    File? f;
    if (catch (f = file::open(path, "ab"))) @die("Cannot truncate open output file.")!;
    f.seek(0)!;

    char[4096] c = bitcast(math::iota(ushort[4096 / 2]), char[4096]);
    usz counter = c.len;

    @verbose("Vomiting iota array into file (%d / %d = %d times).", file_size, c.len, (file_size / c.len));
    while (counter < file_size)
    {
        f.write(c[..])!;
        counter += c.len;
    }

    // Fill in the difference/leftover slice.
    usz leftover = counter - file_size;
    if (leftover)
    {
        @verbose("Vomiting leftovers (%d bytes).", leftover);
        f.write(c[:leftover])!;
    }

    @verbose("File shredded!");
    (void)f.close();
}


fn int main(String[] args) => main_inner(args) ?? 1;

fn int? main_inner(String[] args)
{
    process_options(args)!;

    @verbose("Loading key data.");
    load_key()!;
    defer wipe_mem(options.loaded_key);

    switch (options.operation)
    {
        case ENCRYPT:
            // TODO: Check key requirements if !force
            if (options.stream)
            {
                @info("Starting encryption stream...");

                if (catch oops = mftah::stream_new(options.loaded_key, options.intended_type, options.stream_factor, &read_next_input_block, &yield_next_output_block))
                {
                    @info("An error was encountered while stremaing the new payload.");

                    if (catch try_shred_file(options.output_path))
                    {
                        io::eprintn("\n\n~~~ WARNING:  Failed to shred output file. Remants may still linger and could be recovered. ~~~\n");
                    }

                    @die("Captured fault '%s' during streamed encryption.", oops)!;
                }
            }
            else
            {
                @info("Encrypting...");

                char[]? payload = consume_input();
                if (catch err = payload)
                {
                    @die("Error while consuming input payload:  %s", err)!;
                    return 1;
                }
                defer wipe_mem(payload);

                char[]? encrypted = mftah::new(payload, options.loaded_key, options.intended_type, options.threads, options.fixed_offset);

                if (catch oops = encrypted)
                {
                    (void)@die("Captured fault '%s' during fixed-length encryption.", oops);

                    return oops?;
                }

                flush_output(encrypted);
            }

        case DECRYPT:
            if (options.stream)
            {
                @info("Starting decryption stream...");

                if (catch oops = mftah::stream_decrypt(options.loaded_key, &read_next_input_block, &yield_next_output_block))
                {
                    @info("An error was encountered while decrypting the streamed payload.");

                    if (catch try_shred_file(options.output_path))
                    {
                        io::eprintn("\n\n~~~ WARNING:  Failed to shred output file. Remants may still linger and could be recovered. ~~~\n");
                    }

                    @die("Captured fault '%s' during streamed decryption.", oops)!;
                }
            }
            else
            {
                @info("Decrypting...");

                char[]? payload = consume_input();
                if (catch err = payload)
                {
                    @die("Error while consuming input payload:  %s", err)!;
                    return 1;
                }
                defer wipe_mem(payload);

                char[]? decrypted = mftah::decrypt(payload, options.loaded_key);
                
                if (catch oops = decrypted)
                {
                    if (oops == mftah::PAYLOAD_NOT_FIXED)
                    {
                        @info("Streamed MFTAH payload detected, but '-s' was not specified.\n\tAttempting streamed decryption anyway...\n");

                        options.stream = true;
                        nextcase DECRYPT;
                    }

                    (void)@die("Captured fault '%s' during fixed-length decryption.", oops);

                    return oops?;
                }
            }

        case QUERY:
            io::eprintn("TODO! PAYLOAD INFO");
    }

    return 0;
}
