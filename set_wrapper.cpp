#include <set>
#include <iostream>

extern "C" {

typedef std::set<std::string> StringSet;

StringSet* set_create() {
    return new StringSet;
}

void set_insert(StringSet* set, const char* value) {
    set->insert(value);
}

int set_contains(StringSet* set, const char* value) {
    return set->count(value);
}

void set_remove(StringSet* set, const char* value) {
    set->erase(value);
}

void set_print_all(StringSet* set) {
    for (auto it = set->begin(); it != set->end(); ++it) {
        std::cout << *it << " ";
    }
    std::cout << std::endl;
}

void set_destroy(StringSet* set) {
    delete set;
}

} // extern "C"
