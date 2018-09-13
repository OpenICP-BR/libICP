#pragma once

#ifndef __ICP__NAME_ENTRY__
#define __ICP__NAME_ENTRY__
typedef struct {
	char *key, *val;
} name_entry;
#endif

void set_void_vet_ptr(void **vec, int i, void *ptr);
void set_name_entry_key(name_entry *vec, int i, char *key);
void set_name_entry_val(name_entry *vec, int i, char *val);