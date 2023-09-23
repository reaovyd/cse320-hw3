#include <criterion/criterion.h>
#include <errno.h>
#include <signal.h>
#include "debug.h"
#include "sfmm.h"
#define TEST_TIMEOUT 15

/*
 * Assert the total number of free blocks of a specified size.
 * If size == 0, then assert the total number of all free blocks.
 */
void assert_free_block_count(size_t size, int count) {
    int cnt = 0;
    for(int i = 0; i < NUM_FREE_LISTS; i++) {
	sf_block *bp = sf_free_list_heads[i].body.links.next;
	while(bp != &sf_free_list_heads[i]) {
	    if(size == 0 || size == (bp->header & ~0x7))
		cnt++;
	    bp = bp->body.links.next;
	}
    }
    if(size == 0) {
	cr_assert_eq(cnt, count, "Wrong number of free blocks (exp=%d, found=%d)",
		     count, cnt);
    } else {
	cr_assert_eq(cnt, count, "Wrong number of free blocks of size %ld (exp=%d, found=%d)",
		     size, count, cnt);
    }
}

/*
 * Assert that the free list with a specified index has the specified number of
 * blocks in it.
 */
void assert_free_list_size(int index, int size) {
    int cnt = 0;
    sf_block *bp = sf_free_list_heads[index].body.links.next;
    while(bp != &sf_free_list_heads[index]) {
	cnt++;
	bp = bp->body.links.next;
    }
    cr_assert_eq(cnt, size, "Free list %d has wrong number of free blocks (exp=%d, found=%d)",
		 index, size, cnt);
}

/*
 * Assert the total number of quick list blocks of a specified size.
 * If size == 0, then assert the total number of all quick list blocks.
 */
void assert_quick_list_block_count(size_t size, int count) {
    int cnt = 0;
    for(int i = 0; i < NUM_QUICK_LISTS; i++) {
	sf_block *bp = sf_quick_lists[i].first;
	while(bp != NULL) {
	    if(size == 0 || size == (bp->header & ~0x7))
		cnt++;
	    bp = bp->body.links.next;
	}
    }
    if(size == 0) {
	cr_assert_eq(cnt, count, "Wrong number of quick list blocks (exp=%d, found=%d)",
		     count, cnt);
    } else {
	cr_assert_eq(cnt, count, "Wrong number of quick list blocks of size %ld (exp=%d, found=%d)",
		     size, count, cnt);
    }
}

Test(sfmm_basecode_suite, malloc_an_int, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz = sizeof(int);
	int *x = sf_malloc(sz);

	cr_assert_not_null(x, "x is NULL!");

	*x = 4;

	cr_assert(*x == 4, "sf_malloc failed to give proper space for an int!");

	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 1);
	assert_free_block_count(4024, 1);
	assert_free_list_size(7, 1);

	cr_assert(sf_errno == 0, "sf_errno is not zero!");
	cr_assert(sf_mem_start() + PAGE_SZ == sf_mem_end(), "Allocated more than necessary!");
}

Test(sfmm_basecode_suite, malloc_four_pages, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;

	// We want to allocate up to exactly four pages, so there has to be space
	// for the header and the link pointers.
	void *x = sf_malloc(16336);
	cr_assert_not_null(x, "x is NULL!");
	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 0);
	cr_assert(sf_errno == 0, "sf_errno is not 0!");
}

Test(sfmm_basecode_suite, malloc_too_large, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	void *x = sf_malloc(86100);

	cr_assert_null(x, "x is not NULL!");
	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 1);
	assert_free_block_count(85976, 1);
	cr_assert(sf_errno == ENOMEM, "sf_errno is not ENOMEM!");
}

Test(sfmm_basecode_suite, free_quick, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz_x = 8, sz_y = 32, sz_z = 1;
	/* void *x = */ sf_malloc(sz_x);
	void *y = sf_malloc(sz_y);
	/* void *z = */ sf_malloc(sz_z);

	sf_free(y);

	assert_quick_list_block_count(0, 1);
	assert_quick_list_block_count(40, 1);
	assert_free_block_count(0, 1);
	assert_free_block_count(3952, 1);
	cr_assert(sf_errno == 0, "sf_errno is not zero!");
}

Test(sfmm_basecode_suite, free_no_coalesce, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz_x = 8, sz_y = 200, sz_z = 1;
	/* void *x = */ sf_malloc(sz_x);
	void *y = sf_malloc(sz_y);
	/* void *z = */ sf_malloc(sz_z);

	sf_free(y);

	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 2);
	assert_free_block_count(208, 1);
	assert_free_block_count(3784, 1);

	cr_assert(sf_errno == 0, "sf_errno is not zero!");
}

Test(sfmm_basecode_suite, free_coalesce, .timeout = TEST_TIMEOUT) {
	sf_errno = 0;
	size_t sz_w = 8, sz_x = 200, sz_y = 300, sz_z = 4;
	/* void *w = */ sf_malloc(sz_w);
	void *x = sf_malloc(sz_x);
	void *y = sf_malloc(sz_y);
	/* void *z = */ sf_malloc(sz_z);

	sf_free(y);
	sf_free(x);

	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 2);
	assert_free_block_count(520, 1);
	assert_free_block_count(3472, 1);

	cr_assert(sf_errno == 0, "sf_errno is not zero!");
}

Test(sfmm_basecode_suite, freelist, .timeout = TEST_TIMEOUT) {
        size_t sz_u = 200, sz_v = 300, sz_w = 200, sz_x = 500, sz_y = 200, sz_z = 700;
	void *u = sf_malloc(sz_u);
	/* void *v = */ sf_malloc(sz_v);
	void *w = sf_malloc(sz_w);
	/* void *x = */ sf_malloc(sz_x);
	void *y = sf_malloc(sz_y);
	/* void *z = */ sf_malloc(sz_z);

	sf_free(u);
	sf_free(w);
	sf_free(y);

	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 4);
	assert_free_block_count(208, 3);
	assert_free_block_count(1896, 1);
	assert_free_list_size(3, 3);
	assert_free_list_size(6, 1);
}

Test(sfmm_basecode_suite, realloc_larger_block, .timeout = TEST_TIMEOUT) {
        size_t sz_x = sizeof(int), sz_y = 10, sz_x1 = sizeof(int) * 20;
	void *x = sf_malloc(sz_x);
	/* void *y = */ sf_malloc(sz_y);
	x = sf_realloc(x, sz_x1);

	cr_assert_not_null(x, "x is NULL!");
	sf_block *bp = (sf_block *)((char *)x - sizeof(sf_header));
	cr_assert(bp->header & THIS_BLOCK_ALLOCATED, "Allocated bit is not set!");
	cr_assert((bp->header & ~0x7) == 88, "Realloc'ed block size not what was expected!");

	assert_quick_list_block_count(0, 1);
	assert_quick_list_block_count(32, 1);
	assert_free_block_count(0, 1);
	assert_free_block_count(3904, 1);
}

Test(sfmm_basecode_suite, realloc_smaller_block_splinter, .timeout = TEST_TIMEOUT) {
        size_t sz_x = sizeof(int) * 20, sz_y = sizeof(int) * 16;
	void *x = sf_malloc(sz_x);
	void *y = sf_realloc(x, sz_y);

	cr_assert_not_null(y, "y is NULL!");
	cr_assert(x == y, "Payload addresses are different!");

	sf_block *bp = (sf_block *)((char *)y - sizeof(sf_header));
	cr_assert(bp->header & THIS_BLOCK_ALLOCATED, "Allocated bit is not set!");
	cr_assert((bp->header & ~0x7) == 88, "Realloc'ed block size not what was expected!");

	// There should be only one free block.
	assert_quick_list_block_count(0, 0);
	assert_free_block_count(0, 1);
	assert_free_block_count(3968, 1);
}

Test(sfmm_basecode_suite, realloc_smaller_block_free_block, .timeout = TEST_TIMEOUT) {
        size_t sz_x = sizeof(double) * 8, sz_y = sizeof(int);
	void *x = sf_malloc(sz_x);
	void *y = sf_realloc(x, sz_y);

	cr_assert_not_null(y, "y is NULL!");

	sf_block *bp = (sf_block *)((char *)y - sizeof(sf_header));
	cr_assert(bp->header & THIS_BLOCK_ALLOCATED, "Allocated bit is not set!");
	cr_assert((bp->header & ~0x7) == 32, "Realloc'ed block size not what was expected!");

	// After realloc'ing x, we can return a block of size ADJUSTED_BLOCK_SIZE(sz_x) - ADJUSTED_BLOCK_SIZE(sz_y)
	// to the freelist.  This block will go into the main freelist and be coalesced.
	// Note that we don't put split blocks into the quick lists because their sizes are not sizes
	// that were requested by the client, so they are not very likely to satisfy a new request.
	assert_quick_list_block_count(0, 0);	
	assert_free_block_count(0, 1);
	assert_free_block_count(4024, 1);
}

//############################################
//STUDENT UNIT TESTS SHOULD BE WRITTEN BELOW
//DO NOT DELETE THESE COMMENTS
//############################################

Test(sfmm_student_suite, student_test_1, .timeout = TEST_TIMEOUT) {
    // TEST: malloc returns null if size is 0
    void *x = sf_malloc(0);
    cr_assert_eq(x, NULL, "malloc did not return NULL!");
}

Test(sfmm_student_suite, student_test_2, .timeout = TEST_TIMEOUT) {
    // TEST: write into block
    int *x = sf_malloc(320 * sizeof(int));
    *x = 1;
    *(x + 319) = 0xbeef;

    cr_assert_not_null(x, "malloc returned NULL!");
    cr_assert_eq(*x, 1, "malloc did not set correctly!");
    cr_assert_eq(*(x + 319), 0xbeef, "malloc did not set correctly!");
}

Test(sfmm_student_suite, student_test_3, .timeout = TEST_TIMEOUT) {
    // TEST: freeing puts the block back in a quick list and works in LIFO 
    int *x = sf_malloc(1 * sizeof(int));
    int *x2 = sf_malloc(1 * sizeof(int));
    sf_free(x);
    sf_free(x2);

    cr_assert_eq(sf_quick_lists[0].length, 2, "malloc did not return NULL!");
    cr_assert_eq(sf_quick_lists[0].first, (sf_block *)(((void *) x2) - 8), "LIFO FAILING!");
    cr_assert_eq(sf_quick_lists[0].first->body.links.next, (sf_block *)(((void *) x) - 8), "LIFO FAILING!");
}

Test(sfmm_student_suite, student_test_4, .timeout = TEST_TIMEOUT) {
    // TEST: flushing the qk 
    int *x1 = sf_malloc(1 * sizeof(int));
    int *x2 = sf_malloc(1 * sizeof(int));
    int *x3 = sf_malloc(1 * sizeof(int));
    int *x4 = sf_malloc(1 * sizeof(int));
    int *x5 = sf_malloc(1 * sizeof(int));
    int *x6 = sf_malloc(1 * sizeof(int));

    sf_free(x2);
    sf_free(x3);
    sf_free(x5);
    sf_free(x4);
    sf_free(x1);

    cr_assert_eq(sf_quick_lists[0].length, 5, "malloc did not return NULL!");
    sf_free(x6);
    cr_assert_eq(sf_quick_lists[0].length, 1, "Expected %d but got %d", 1, sf_quick_lists[0].length);
    cr_assert_eq(sf_quick_lists[0].first, (sf_block *)(((void *) x6) - 8), "Expected %p to be only element in quick list", x6);
}

Test(sfmm_student_suite, student_test_5, .timeout = TEST_TIMEOUT) {
    // TEST: freeing a large block 
    double *x1 = sf_malloc(1288 * sizeof(double));

    for(int i = 0; i < 1288; i += 2) {
        x1[i] = 3.2;
    }

    for(int i = 0; i < 1288; i += 2) {
        cr_assert_eq(x1[i], 3.2, "Expected %f but got %f", 3.2, x1[i]);
    }

    sf_free(x1);

    cr_assert_eq(sf_free_list_heads[NUM_FREE_LISTS - 1].body.links.next->header & ~0x7, 12248, "Expected %d but got %d", 12248, sf_free_list_heads[NUM_FREE_LISTS - 1].body.links.next->header & ~0x7);
}

Test(sfmm_student_suite, student_test_6, .timeout = TEST_TIMEOUT, .signal = SIGABRT) {
    // TEST: testing all invalid pointers 
    void *ptr = NULL;
    sf_free(ptr);
}

Test(sfmm_student_suite, student_test_7, .timeout = TEST_TIMEOUT, .signal = SIGABRT) {
    // TEST: testing all invalid pointers 
    void *ptr = (void *)0x9;
    sf_free(ptr);
}

Test(sfmm_student_suite, student_test_8, .timeout = TEST_TIMEOUT, .signal = SIGABRT) {
    // TEST: testing all invalid pointers 
    void *ptr = (void *)0x20;
    sf_free(ptr);
}

Test(sfmm_student_suite, student_test_9, .timeout = TEST_TIMEOUT, .signal = SIGABRT) {
    // TEST: testing all invalid pointers 
    void *ptr = (void *)0x100000000000;
    sf_free(ptr);
}

Test(sfmm_student_suite, student_test_10, .timeout = TEST_TIMEOUT, .signal = SIGABRT) {
    // TEST: testing all invalid pointers 
    int *tmp = sf_malloc(sizeof(int));

    sf_header *hdr = ((void *)tmp - 8);
    *hdr &= ~THIS_BLOCK_ALLOCATED;

    sf_free(tmp);
}

Test(sfmm_student_suite, student_test_11, .timeout = TEST_TIMEOUT, .signal = SIGABRT) {
    // TEST: testing all invalid pointers 
    int *tmp = sf_malloc(sizeof(int));

    sf_header *hdr = ((void *)tmp - 8);
    *hdr |= IN_QUICK_LIST;

    sf_free(tmp);
}

Test(sfmm_student_suite, student_test_12, .timeout = TEST_TIMEOUT) {
    // TEST: default failing einval sf_errno  
    void *ret = sf_memalign(0, 6);
    cr_assert_null(ret, "Got NULL result!");
    cr_assert_eq(sf_errno, EINVAL, "Expected EINVAL for sf_errno");
}

Test(sfmm_student_suite, student_test_13, .timeout = TEST_TIMEOUT) {
    // TEST: default failing einval sf_errno  
    void *ret = sf_memalign(0, 63);
    cr_assert_null(ret, "Got NULL result!");
    cr_assert_eq(sf_errno, EINVAL, "Expected EINVAL for sf_errno");
}

Test(sfmm_student_suite, student_test_14, .timeout = TEST_TIMEOUT) {
    // TEST: default failing einval sf_errno  
    void *ret = sf_memalign(1, 16);
    cr_assert((size_t)ret % 16 == 0, "Not aligned!");
}

Test(sfmm_student_suite, student_test_15, .timeout = TEST_TIMEOUT) {
    double *ptr1= sf_memalign(240 * sizeof(double), 16);
    double *ptr2= sf_memalign(240 * sizeof(double), 64);
    double *ptr3= sf_memalign(240 * sizeof(double), 128);
    double *ptr4= sf_memalign(240 * sizeof(double), 256);
    cr_assert((size_t)ptr1 % 16 == 0, "ptr1 Not aligned with %d!", 16);
    cr_assert((size_t)ptr2 % 64 == 0, "ptr2 Not aligned with %d!", 64);
    cr_assert((size_t)ptr3 % 128 == 0, "ptr3 Not aligned with %d!", 128);
    cr_assert((size_t)ptr4 % 256 == 0, "ptr4 Not aligned with %d!", 256);
}

Test(sfmm_student_suite, student_test_16, .timeout = TEST_TIMEOUT) {
    double *ptr1= sf_memalign(103, 16);
    double *ptr2= sf_memalign(107, 64);
    double *ptr3= sf_memalign(113, 128);
    double *ptr4= sf_memalign(47, 256);
    cr_assert((size_t)ptr1 % 16 == 0, "ptr1 Not aligned with %d!", 16);
    cr_assert((size_t)ptr2 % 64 == 0, "ptr2 Not aligned with %d!", 64);
    cr_assert((size_t)ptr3 % 128 == 0, "ptr3 Not aligned with %d!", 128);
    cr_assert((size_t)ptr4 % 256 == 0, "ptr4 Not aligned with %d!", 256);

    sf_free(ptr3);
    sf_free(ptr2);
    cr_assert((size_t)ptr1 % 16 == 0, "ptr1 Not aligned with %d!", 16);
    cr_assert((size_t)ptr4 % 256 == 0, "ptr4 Not aligned with %d!", 256);
}

Test(sfmm_student_suite, student_test_17, .timeout = TEST_TIMEOUT) {
    // TEST: quick list stuff
    double *ptr1= sf_memalign(sizeof(double), 64);
    double *ptr2= sf_memalign(sizeof(double), 128);
    double *ptr3 = sf_memalign(sizeof(double), 256);
    double *ptr4 = sf_memalign(sizeof(double), 512);
    double *ptr5 = sf_memalign(sizeof(double), 1024);
    double *ptr6 = sf_memalign(sizeof(double), 2048);

    cr_assert((size_t)ptr1 % 1<<6 == 0, "ptr1 Not aligned with %d!", 1<<6);
    cr_assert((size_t)ptr2 % 1<<7 == 0, "ptr2 Not aligned with %d!", 1<<7);
    cr_assert((size_t)ptr3 % 1<<8 == 0, "ptr3 Not aligned with %d!", 1<<8);
    cr_assert((size_t)ptr4 % 1<<9 == 0, "ptr4 Not aligned with %d!", 1<<9);
    cr_assert((size_t)ptr5 % 1<<10 == 0, "ptr4 Not aligned with %d!", 1<<10);
    cr_assert((size_t)ptr6 % 1<<11 == 0, "ptr4 Not aligned with %d!", 1<<11);

    sf_free(ptr1);
    sf_free(ptr2);
    sf_free(ptr3);
    sf_free(ptr4);
    sf_free(ptr5);
    cr_assert(sf_quick_lists[0].length == 5, "Expected quick list length to be %d!", 5);
    sf_free(ptr6);
    cr_assert(sf_quick_lists[0].length == 1, "Expected quick list length to be %d!", 1);
}
