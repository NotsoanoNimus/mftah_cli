module mftah_cli;

import mftah;
import opt;

import std::thread;
import std::os;
import std::io;


const DEFAULT_THREADS = 8;


const char[] USAGE_TEXT = $embed("usage.txt");

macro @usage()
{
    io::printf(USAGE_TEXT, DEFAULT_THREADS);
    os::exit(1);
}

macro @version_info()
{
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

    char threads;

    CliOperation operation;

    String output_path;
    String input_path;

    String keyfile_path;
    String key;

    String new_keyfile_path;
    String new_key;
}
CliOptions options;

fn void process_options(String[] args)
{
    bool is_query, is_encrypt, is_decrypt, is_rekey, needs_help, wants_version;

    if (catch opt::@parse(
        args,
        "h", "help", &needs_help,
        "q", "query", &is_query,
        "e", "encrypt", &is_encrypt,
        "d", "decrypt", &is_decrypt,
        "r", "rekey", &is_rekey,
        "s", "stream", &options.stream,
        "o", "output", &options.output_path,
        "i", "input", &options.input_path,
        "k", "key", &options.key,
        "K", "keyfile", &options.keyfile_path,
        "c", "change-key", &options.new_key,
        "C", "change-keyfile", &options.new_keyfile_path,
        "t", "threads", &options.threads,
        "F", "force-key", &options.force_key,
        "n", "noninteractive", &options.noninteractive,
        "v", "version", &wants_version,
    )) @usage();

    if (needs_help) @usage();

    if (wants_version) @version_info();

    if ((char)is_query + (char)is_encrypt + (char)is_decrypt + (char)is_rekey > 1)
    {
        io::eprintn("You can only choose one operation: query (-q), encrypt (-e), decrypt (-d), or rekey (-r).");
        os::exit(1);
    }

    switch
    {
        case is_encrypt: options.operation = ENCRYPT;
        case is_decrypt: options.operation = DECRYPT;
        case is_rekey: options.operation = REKEY;
        case is_query: options.operation = QUERY;

        default:
            io::eprintn("You must supply at least one operation: query (-q), encrypt (-e), decrypt (-d), or rekey (-r).");
    }

    // Options are largely regarded/selected based on the chosen mode.
    //   But first, make sure the user isn't doing a bad thing.
    // if ()
}


fn int main(String[] args)
{
    process_options(args);

    return 0;
}
