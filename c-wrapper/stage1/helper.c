#include "helper.h"

void set_void_vet_ptr(void **vec, int i, void *ptr) {
	vec[i] = ptr;
}

void set_name_entry_key(name_entry *vec, int i, char *key) {
	vec[i].key = key;
}

void set_name_entry_val(name_entry *vec, int i, char *val) {
	vec[i].val = val;
}
