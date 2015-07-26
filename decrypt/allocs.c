/* Memory pools */
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

#include "allocs.h"

#define ALLOC_SIZE (16 * 1024)
#define ALIGN_BYTES (sizeof(void *))

struct pool {
	struct pool *prev;
	size_t size;
	size_t remaining;
	size_t next_alloc;
};

static struct pool *current = NULL;

int pool_push()
{
	struct pool *new = malloc(ALLOC_SIZE);

	if(new == NULL)
		return -1;

	new->prev = current;
	new->size = ALLOC_SIZE;
	new->remaining = ALLOC_SIZE - sizeof(struct pool);
	new->next_alloc = sizeof(struct pool);

	current = new;
	return 0;
}

int pool_pop()
{
	struct pool *old_current = current;

	current = current->prev;

	free(old_current);
	return 0;
}

void pool_exit(void)
{
	while(current != NULL)
		pool_pop();
}

int pool_init()
{
	atexit(pool_exit);
	current = NULL;
	return pool_push();
}

void *pool_alloc(size_t length)
{
	assert(current != NULL);

	if(length == 0)
		return NULL;

	length = (length + (ALIGN_BYTES - 1)) & (~(ALIGN_BYTES - 1));

	if(current->remaining < length) {
		size_t bytes_to_add = (current->size > length ? current->size : length);

		if((bytes_to_add & (bytes_to_add - 1)) != 0) {
			if(sizeof(size_t) == 4) {
				/* Round to next power of two */
				bytes_to_add = 1 << (32 - __builtin_clz(bytes_to_add));
			} else if (sizeof(size_t) == 8) {
				bytes_to_add = 1 << (64 - __builtin_clzl(bytes_to_add));
			} else {
				assert(!"implement me");
			}
		}

		struct pool *new_current = realloc(current, current->size + bytes_to_add);
		if(new_current == NULL)
			return NULL;
		else
			current = new_current;

		current->remaining += bytes_to_add;
		current->size += bytes_to_add;
	}

	void *alloc = ((uint8_t *)current) + current->next_alloc;

	current->next_alloc += length;
	current->remaining -= length;

	return alloc;
}

void pool_free(void *ptr)
{
}

void _pool_print_current(void)
{
	printf("current %p\n", current);
}

