#ifndef SET_WRAPPER_H
#define SET_WRAPPER_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct StringSet StringSet;

StringSet* set_create();
void set_insert(StringSet* set, const char* value);
int set_contains(StringSet* set, const char* value);
void set_remove(StringSet* set, const char* value);
void set_print_all(StringSet* set);
void set_destroy(StringSet* set);

#ifdef __cplusplus
}
#endif

#endif // SET_WRAPPER_H
