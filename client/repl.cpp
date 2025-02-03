#include "repl.hpp"
#include <iostream>

void print_actions();

/// Read-Eval-Print loop for user interaction.
void repl() {
    // Notify the user about the available actions.
    print_actions();
}


void print_actions() {
    std::cout << "1. Add documents\n";
    std::cout << "2. Delete documents\n";
    std::cout << "3. Search keywords\n";

    std::cout.flush();
}
