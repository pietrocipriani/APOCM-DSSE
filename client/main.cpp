#include "argparse.hpp"
#include "protocol.hpp"
#include "utils.hpp"
#include <cstdlib>
#include <utility>
#include <functional>
#include <sockpp/unix_stream_socket.h>

#define SOCK_ADDR "\0dsse_apocm"

int main(int argc, const char **argv) {
    sockpp::initialize();
    
    Args args;

    try {
        args = parse_action(argc, argv);
    } catch (const std::invalid_argument& e) {
        std::cerr << "[ERROR]" << e.what() << "." << std::endl;
        return EXIT_FAILURE;
    }


    try {

        Protocol<32> dsse(SOCK_ADDR);

        std::visit(overload{
            [&](const ArgsAdd& args) { dsse.add(args); },
            [&](const ArgsRemove& args) { dsse.remove(args); },
            [&](const ArgsSearch& args) { dsse.search(args); },
        }, args);

    } catch (const KeysNotFound& e) {
        std::cerr << "[ERROR]" << e.what() << "." << std::endl;
        return EXIT_FAILURE;
    } catch (const CorruptedKeys& e) {
        std::cerr << "[ERROR]" << e.what() << "." << std::endl;
        return EXIT_FAILURE;
    } catch (const std::runtime_error& e) {
        std::cerr << "[ERROR]" << e.what() << "." << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
