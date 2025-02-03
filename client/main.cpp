#include "argparse.hpp"
#include "protocol.hpp"
#include "utils.hpp"
#include <cstdlib>
#include <utility>
#include <functional>

int main(int argc, const char **argv) {
    
    Args args;

    try {
        args = parse_action(argc, argv);
    } catch (const std::invalid_argument& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }


    Protocol dsse;

    std::visit(overload{
        [&](const ArgsAdd& args) { dsse.add(args); },
        [&](const ArgsRemove& args) { dsse.remove(args); },
        [&](const ArgsSearch& args) { dsse.search(args); },
    }, args);

    return EXIT_SUCCESS;
}
