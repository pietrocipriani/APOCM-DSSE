#pragma once

#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <filesystem>
#include <uuid/uuid.h>
#include <Monocypher.hh>


enum class Action { add = 0, remove = 1, search = 2 };

using Path = std::filesystem::path;
using Keyword = std::string;
using DocId = monocypher::byte_array<sizeof(uuid_t)>;

struct ArgsAdd { std::vector<Path> paths; };
struct ArgsRemove { std::vector<DocId> ids; };
struct ArgsSearch { std::vector<Keyword> keywords; };

using Args = std::variant<ArgsAdd, ArgsRemove, ArgsSearch>;

// Custom implementation for this simple case.
/// @return a list of arguments (their interpretation depends on the action: paths, ids or keywords).
Args parse_action(int argc, const char **argv);
