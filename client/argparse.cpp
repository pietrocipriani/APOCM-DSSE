#include "argparse.hpp"

#include <string>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <utility>


void print_usage(const char *program_name) {
    using std::cerr;
    cerr << "Usage:\n";
    cerr << program_name << " add file...\n";
    cerr << program_name << " remove document_id...\n";
    cerr << program_name << " search keyword...\n";
    cerr.flush();
}


std::optional<Action> parse_action(const std::string& raw_action) {
    if (raw_action == "add") {
        return Action::add;
    } else if (raw_action == "remove") {
        return Action::remove;
    } else if (raw_action == "search") {
        return Action::search;
    }
    return std::nullopt;
}


ArgsAdd parse_add([[maybe_unused]] int argc, [[maybe_unused]] const char **argv) {
    return {};
}
ArgsRemove parse_remove([[maybe_unused]] int argc, [[maybe_unused]] const char **argv) {
    return {};
}
ArgsSearch parse_search([[maybe_unused]] int argc, [[maybe_unused]] const char **argv) {
    return {};
}

Args parse_args(const Action& action, int argc, const char **argv) {
    switch(action) {
        case Action::add: 
            return parse_add(argc, argv);
        case Action::remove:
            return parse_remove(argc, argv);
        case Action::search: 
            return parse_search(argc, argv);
        default:
            throw std::invalid_argument("Invalid action. Choose between add, remove and search.");
    }
}


// Custom implementation for this simple case.
/// @return a list of arguments (their interpretation depends on the action: paths, ids or keywords).
Args parse_action(int argc, const char **argv) {

    if (argc <= 1) {
        print_usage(argc == 1 ? argv[0] : "client");
        throw std::invalid_argument("Arguments are needed");
    }

    auto action_opt = parse_action(argv[1]);
    if (action_opt) {
        const Action action = *action_opt;

        // Shift-out the first two arguments.
        argc -= 2;
        // NOTE: argv can become invalid, however only if argc == 0.
        // Set to null to trigger exceptions in case of coding errors.
        argv = argc == 0 ? nullptr : argv - 2;
        
        return parse_args(action, argc, argv);
    } else {
        throw std::invalid_argument("Invalid action. Choose between add, remove and search.");
    }

}
