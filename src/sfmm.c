/**
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "debug.h"
#include "sfmm.h"

#define BLK_SIZE_MIN 32
#define WORD_SIZE_ALIGN 8

#define EMPTY_QK_LST(idx) (sf_quick_lists[idx].length == 0)
#define GET_BLK_HDR_SZ(hdr) ((hdr) & (~(0x7)))

#define GET_BLK_FTR(blk_ptr) (((void *)(blk_ptr)) + GET_BLK_HDR_SZ(blk_ptr->header) - WORD_SIZE_ALIGN) 

#define GET_ADJ_NXT_BLK(blk_ptr) ((void *)(blk_ptr) + GET_BLK_HDR_SZ(blk_ptr->header))
#define SET_NEW_EPILOGUE(new_epilogue_ptr) ((EPILOGUE_PTR) = (sf_header *)(new_epilogue_ptr))

#define SET_DEFAULT_PAD_SIZE(size) pad_size(size, WORD_SIZE_ALIGN)

static sf_block *PROLOGUE_PTR;
static sf_header *EPILOGUE_PTR;

static int get_qk_idx(size_t size) {
    size_t offset = BLK_SIZE_MIN;

    for(int idx = 0; idx < NUM_QUICK_LISTS; ++idx) {
        if(size == (offset + (idx << 3))) {
            return idx;
        }
    }

    return -1;
}

static size_t pad_size(size_t size, size_t mod) {
    if(size < BLK_SIZE_MIN) {
        return BLK_SIZE_MIN;
    }
    size_t remainder = size % mod;
    if(!(remainder)) {
        return size;
    }
    return size + mod - remainder;
}

static void initialize_free_lists() {
    for(int flist_idx = 0; flist_idx < NUM_FREE_LISTS; ++flist_idx) {
        sf_free_list_heads[flist_idx].body.links.next = &sf_free_list_heads[flist_idx];
        sf_free_list_heads[flist_idx].body.links.prev = &sf_free_list_heads[flist_idx];
    }
}

static int get_flst_idx(size_t size) {
    int flst_idx = 0;

    if(size == BLK_SIZE_MIN) {
        flst_idx = 0;
    } else if(size > BLK_SIZE_MIN << 8) {
        flst_idx = 9;
    } else {
        while(flst_idx < NUM_FREE_LISTS) {
            if(size > BLK_SIZE_MIN << flst_idx && size <= BLK_SIZE_MIN << (flst_idx + 1)) {
                ++flst_idx;
                break;
            }
            ++flst_idx;
        }
    }
    return flst_idx;
}

static void push_front_free_lst(sf_block *free_blk) {
    int flst_idx = get_flst_idx((size_t)free_blk->header);
    sf_block *old_head = sf_free_list_heads[flst_idx].body.links.next;

    free_blk->body.links.next = old_head;
    free_blk->body.links.prev = &sf_free_list_heads[flst_idx];

    old_head->body.links.prev = free_blk;
    sf_free_list_heads[flst_idx].body.links.next = free_blk; 
}

// useful for removing an allocated block from the free list
static sf_block *remove_blk_from_lst(sf_block *free_blk) {
    sf_block *nxt_blk = free_blk->body.links.next;
    sf_block *prv_blk = free_blk->body.links.prev;

    nxt_blk->body.links.prev = prv_blk;
    prv_blk->body.links.next = nxt_blk;

    free_blk->body.links.next = NULL;
    free_blk->body.links.prev = NULL;

    return free_blk;

}

static void set_nxt_prv_a(sf_block *free_blk) {
    sf_block *nxt_blk_ptr = (sf_block *)GET_ADJ_NXT_BLK(free_blk);
    nxt_blk_ptr->header |= PREV_BLOCK_ALLOCATED;
    if(!(nxt_blk_ptr->header & THIS_BLOCK_ALLOCATED)) {
        sf_footer *nxt_blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(nxt_blk_ptr);
        *nxt_blk_ftr_ptr = nxt_blk_ptr->header;
    }
}

static void clear_nxt_prv_a(sf_block *free_blk) {
    sf_block *nxt_blk_ptr = (sf_block *)GET_ADJ_NXT_BLK(free_blk);
    nxt_blk_ptr->header &= ~PREV_BLOCK_ALLOCATED;
    if(!(nxt_blk_ptr->header & THIS_BLOCK_ALLOCATED)) {
        sf_footer *nxt_blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(nxt_blk_ptr);
        *nxt_blk_ftr_ptr = nxt_blk_ptr->header;
    }
}

static void allocate_block(sf_block *free_blk, size_t alloc_size) {
    remove_blk_from_lst(free_blk);

    size_t prv_alloc_set = free_blk->header & PREV_BLOCK_ALLOCATED;
    free_blk->header = alloc_size | prv_alloc_set;
    free_blk->header |= THIS_BLOCK_ALLOCATED;

    set_nxt_prv_a(free_blk);
    // also set prev_alloc of next block
}

// return 1 if splitting could not be done; return 0 if splitting could be done
static bool allocate_and_split_block(sf_block *free_blk, size_t alloc_size) {
    size_t remainder = GET_BLK_HDR_SZ(free_blk->header) - alloc_size;
    
    if(remainder < BLK_SIZE_MIN) {
        allocate_block(free_blk, GET_BLK_HDR_SZ(free_blk->header));
        return true;
    }

    sf_header *new_ftr_ptr = (sf_header *)GET_BLK_FTR(free_blk);
    sf_block  *new_hdr_ptr = (sf_block *)(((void *)free_blk) + alloc_size);

    allocate_block(free_blk, alloc_size);

    new_hdr_ptr->body.links.prev = NULL;
    new_hdr_ptr->body.links.next = NULL;

    new_hdr_ptr->header = remainder;
    new_hdr_ptr->header |= PREV_BLOCK_ALLOCATED;

    *new_ftr_ptr = new_hdr_ptr->header;

    push_front_free_lst(new_hdr_ptr);
    return false;
}

static sf_block *find_first_fit(size_t alloc_size) {
    int initial_idx = get_flst_idx(alloc_size);

    sf_block *blk_fit = NULL;

    while(initial_idx < NUM_FREE_LISTS && !blk_fit) {
        sf_block *sentinel = &sf_free_list_heads[initial_idx];
        sf_block *next_node = sentinel->body.links.next;

        while(next_node != sentinel) {
            if(alloc_size <= GET_BLK_HDR_SZ(next_node->header)) {
                blk_fit = next_node;
                break;
            }
            next_node = next_node->body.links.next;
        }

        ++initial_idx;
    }

    return blk_fit;
}

// assuming current block is freed 
static void coalesce(sf_block *blk) {
    size_t is_prv_alloced = blk->header & PREV_BLOCK_ALLOCATED;
    if(is_prv_alloced) {
        sf_block *nxt_blk_ptr = (sf_block *)GET_ADJ_NXT_BLK(blk);
        if(!(nxt_blk_ptr->header & THIS_BLOCK_ALLOCATED)) {
            remove_blk_from_lst(nxt_blk_ptr);
            remove_blk_from_lst(blk);
            size_t new_sz = GET_BLK_HDR_SZ(nxt_blk_ptr->header) + GET_BLK_HDR_SZ(blk->header);
            size_t save_old_bits = blk->header & 0x7;
            new_sz |= save_old_bits;

            blk->header = new_sz;
            sf_footer *ftr_ptr = (sf_footer *)GET_BLK_FTR(nxt_blk_ptr);
            *ftr_ptr = blk->header;

            push_front_free_lst(blk);
        }
    } else {
        sf_footer *prv_blk_footer = ((void *)blk) - WORD_SIZE_ALIGN;
        size_t old_blk_sz = GET_BLK_HDR_SZ(*prv_blk_footer);
        sf_block *prv_blk = ((void *)blk) - old_blk_sz;

        sf_block *nxt_blk_ptr = (sf_block *)GET_ADJ_NXT_BLK(blk);
        if(!(nxt_blk_ptr->header & THIS_BLOCK_ALLOCATED)) {
            remove_blk_from_lst(blk);
            remove_blk_from_lst(nxt_blk_ptr);
            remove_blk_from_lst(prv_blk);

            size_t new_sz = GET_BLK_HDR_SZ(nxt_blk_ptr->header) + GET_BLK_HDR_SZ(blk->header) + GET_BLK_HDR_SZ(prv_blk->header);
            size_t save_old_bits = prv_blk->header & 0x7;
            new_sz |= save_old_bits;

            prv_blk->header = new_sz;
            sf_footer *ftr_ptr = (sf_footer *)GET_BLK_FTR(nxt_blk_ptr);
            *ftr_ptr = prv_blk->header;

            push_front_free_lst(prv_blk);
        } else {
            remove_blk_from_lst(blk);
            remove_blk_from_lst(prv_blk);

            size_t new_sz = GET_BLK_HDR_SZ(blk->header) + GET_BLK_HDR_SZ(prv_blk->header);

            size_t save_old_bits = prv_blk->header & 0x7;
            new_sz |= save_old_bits;

            prv_blk->header = new_sz;
            sf_footer *ftr_ptr = (sf_footer *)GET_BLK_FTR(blk);
            *ftr_ptr = prv_blk->header;

            push_front_free_lst(prv_blk);
        }

    }
}

static bool is_valid_pointer(void *ptr) {
    if(ptr == NULL) {
        return false;
    }
    size_t ptr_val = (size_t)ptr;
    if(ptr_val % WORD_SIZE_ALIGN) {
        return false;
    }
    void *v_hdr = ptr - WORD_SIZE_ALIGN;
    if((v_hdr < sf_mem_start()) || (v_hdr > sf_mem_end())) {
        return false;
    }

    sf_header *s_hdr = (sf_header *)v_hdr;
    if(!(*s_hdr & THIS_BLOCK_ALLOCATED)) {
        return false;
    }

    if(*s_hdr & IN_QUICK_LIST) {
        return false;
    }

    if(!(*s_hdr & PREV_BLOCK_ALLOCATED)) {
        sf_footer *prv_ftr = (sf_footer *)((void *)s_hdr - WORD_SIZE_ALIGN);
        if(*prv_ftr & THIS_BLOCK_ALLOCATED) {
            return false;
        }
    }

    size_t hdr_sz = GET_BLK_HDR_SZ(*s_hdr);

    if(hdr_sz < BLK_SIZE_MIN) {
        return false;
    }
    if(hdr_sz % WORD_SIZE_ALIGN) {
        return false;
    }

    return true;
}

static void push_front_qk_lst(sf_block *new_block, int qk_lst_idx) {
    size_t sz = sf_quick_lists[qk_lst_idx].length;
    if(sz == 0) {
        new_block->body.links.next = NULL;
    } else {
        new_block->body.links.next = sf_quick_lists[qk_lst_idx].first;
    }
    sf_quick_lists[qk_lst_idx].first = new_block;
    sf_quick_lists[qk_lst_idx].length = sz + 1;

    new_block->header |= IN_QUICK_LIST;
}

static sf_block *pop_front_qk_lst(int qk_lst_idx) {
    sf_quick_lists[qk_lst_idx].length--;
    sf_block *ret = sf_quick_lists[qk_lst_idx].first;
    if(sf_quick_lists[qk_lst_idx].length == 0) {
        sf_quick_lists[qk_lst_idx].first = NULL;
    } else {
        sf_quick_lists[qk_lst_idx].first = ret->body.links.next;
        ret->body.links.next = NULL;
    }
    ret->header &= ~IN_QUICK_LIST;
    return ret;
}

void *sf_malloc(size_t size) {
    void *ret = NULL;
    if(size == 0) {
        return ret;
    }
    size_t allocated_size = SET_DEFAULT_PAD_SIZE(size + sizeof(sf_header));
    int qk_idx = get_qk_idx(allocated_size);

    if(qk_idx != -1 && !EMPTY_QK_LST(qk_idx)) {
        sf_block *qk_blk = (sf_block *)pop_front_qk_lst(qk_idx);
        ret = &(qk_blk->body.payload);
    } else {
        void *start_ptr = sf_mem_start();
        void *end_ptr = sf_mem_end();

        if(start_ptr == end_ptr) {
            void *heap_ptr = sf_mem_grow(); 
            if(heap_ptr == NULL) {
                sf_errno = ENOMEM;
                return NULL;
            }
            end_ptr = sf_mem_end();
            PROLOGUE_PTR = (sf_block *)start_ptr;
            PROLOGUE_PTR->header |= THIS_BLOCK_ALLOCATED;
            PROLOGUE_PTR->header |= BLK_SIZE_MIN; // set size to 32

            //EPILOGUE_PTR = (sf_header *)(end_ptr - WORD_SIZE_ALIGN);
            SET_NEW_EPILOGUE(end_ptr - WORD_SIZE_ALIGN);
            *EPILOGUE_PTR |= THIS_BLOCK_ALLOCATED;  

            size_t first_free_blk_size = PAGE_SZ - GET_BLK_HDR_SZ(PROLOGUE_PTR->header) - sizeof(sf_header); 

            sf_block *first_free_blk_ptr = ((void *)PROLOGUE_PTR) + GET_BLK_HDR_SZ(PROLOGUE_PTR->header);

            first_free_blk_ptr->header = first_free_blk_size;
            first_free_blk_ptr->header |= PREV_BLOCK_ALLOCATED;

            sf_footer *first_ftr_ptr = (((void *)first_free_blk_ptr) + GET_BLK_HDR_SZ(first_free_blk_ptr->header)) - sizeof(sf_footer);

            *first_ftr_ptr = first_free_blk_ptr->header; 

            initialize_free_lists();
            push_front_free_lst(first_free_blk_ptr);
        }

        sf_block *fb = NULL;
        while(fb == NULL) {
            fb = find_first_fit(allocated_size);
            if(fb == NULL) {
                void *old_end_ptr = sf_mem_grow();
                if(old_end_ptr == NULL) {
                    sf_errno = ENOMEM;
                    return NULL;
                }
                sf_header *old_epilogue_hdr = EPILOGUE_PTR; 
                SET_NEW_EPILOGUE(sf_mem_end() - WORD_SIZE_ALIGN);
                *EPILOGUE_PTR |= THIS_BLOCK_ALLOCATED; 

                sf_block *new_sf_block = (sf_block *)old_epilogue_hdr;
                new_sf_block->header |= PAGE_SZ;
                new_sf_block->header &= ~THIS_BLOCK_ALLOCATED;

                sf_footer *ftr_ptr = (sf_footer *)GET_BLK_FTR(new_sf_block);
                *ftr_ptr = new_sf_block->header;

                push_front_free_lst(new_sf_block);
                coalesce(new_sf_block);
            }
        }
        allocate_and_split_block(fb, allocated_size);
        ret = &(fb->body.payload);
    }
    return ret; 
}

void sf_free(void *pp) {
    if(!is_valid_pointer(pp)) {
        return abort();
    }

    sf_block *blk_ptr = (sf_block *)((void *)pp - WORD_SIZE_ALIGN);
    size_t blk_sz = GET_BLK_HDR_SZ(blk_ptr->header);
    int qk_idx = get_qk_idx(blk_sz);

    if(qk_idx != -1) {
        if(sf_quick_lists[qk_idx].length >= QUICK_LIST_MAX) {
            while(sf_quick_lists[qk_idx].length) {
                // bit clears the IN_QK_LST
                sf_block *new_blk = pop_front_qk_lst(qk_idx);
                new_blk->header &= ~THIS_BLOCK_ALLOCATED; 

                sf_footer *ftr_ptr = (sf_footer *)GET_BLK_FTR(new_blk);
                *ftr_ptr = new_blk->header;

                clear_nxt_prv_a(new_blk);

                push_front_free_lst(new_blk);
                coalesce(new_blk);
            }
        }
        // bit sets the IN_QK_LST
        push_front_qk_lst(blk_ptr, qk_idx);
    } else {
        blk_ptr->header &= ~THIS_BLOCK_ALLOCATED; 
        sf_footer *blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(blk_ptr);
        *blk_ftr_ptr = blk_ptr->header;

        clear_nxt_prv_a(blk_ptr);

        push_front_free_lst(blk_ptr);
        coalesce(blk_ptr);
    }
}

void *sf_realloc(void *pp, size_t rsize) {
    if(!is_valid_pointer(pp)) {
        sf_errno = EINVAL;
        return NULL;  
    }
    if(rsize == 0) {
        sf_free(pp);
        return NULL;
    }

    sf_block *blk_hdr = (sf_block *)(pp - WORD_SIZE_ALIGN);
    size_t blk_sz = GET_BLK_HDR_SZ(blk_hdr->header);
    size_t new_alloc_size = SET_DEFAULT_PAD_SIZE(rsize);  

    if(new_alloc_size == blk_sz) {
        return pp;
    }
    void *ret = NULL;
    if(new_alloc_size > blk_sz) {
        // rsize has overhead added anyways in malloc
        void *payload_start = sf_malloc(rsize); 
        if(payload_start == NULL) {
            return NULL;
        }
        memcpy(payload_start, pp, GET_BLK_HDR_SZ(blk_hdr->header) - sizeof(sf_header));
        sf_free(pp);
        ret = payload_start;
    } else {
        // since new_alloc_Size is less than the blk_sz we can just use the old blk_sz
        size_t remainder = blk_sz - new_alloc_size; 
        if(remainder < BLK_SIZE_MIN) {
            ret = pp;
        } else {
            // trhe  remainder block should be coalesced with the block on the right of it
            // the block blk_hdr is allocated
            size_t save_old_bits = blk_hdr->header & 0x7; 
            blk_hdr->header = new_alloc_size | save_old_bits;

            sf_block *nxt_blk_ptr = (sf_block *)GET_ADJ_NXT_BLK(blk_hdr);
            nxt_blk_ptr->header = remainder | PREV_BLOCK_ALLOCATED;

            sf_footer *nxt_blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(nxt_blk_ptr);
            *nxt_blk_ftr_ptr = nxt_blk_ptr->header;

            push_front_free_lst(nxt_blk_ptr);
            coalesce(nxt_blk_ptr);

            ret = (void *)blk_hdr + WORD_SIZE_ALIGN;
        }
    }
    return ret;
}

void *sf_memalign(size_t size, size_t align) {
    if(align < WORD_SIZE_ALIGN || (align & (align - 1))) {
        sf_errno = EINVAL;
        return NULL;
    }
    if(size == 0) {
        return NULL;
    }

    size_t allocated_size = SET_DEFAULT_PAD_SIZE(size + align + BLK_SIZE_MIN + sizeof(sf_header)
            + sizeof(sf_footer));
    int qk_idx = get_qk_idx(allocated_size);
    void *ret = NULL;

    if(qk_idx != -1 && !EMPTY_QK_LST(qk_idx)) {
        sf_block *qk_blk = (sf_block *)pop_front_qk_lst(qk_idx);

        void *old_payload_ptr = &(qk_blk->body.payload);
        if(((size_t)old_payload_ptr) % align) {
            sf_header *old_header = (sf_header *)(old_payload_ptr - WORD_SIZE_ALIGN);
            // guaranteed that the remainder 
            void *new_payload_ptr = (void *)pad_size((size_t)(old_payload_ptr + BLK_SIZE_MIN), align);
            sf_header *new_header = (sf_header *)(new_payload_ptr - WORD_SIZE_ALIGN);

            size_t top_split_sz = (void *)new_header - (void *)old_header;
            size_t remainder_from_top = GET_BLK_HDR_SZ(qk_blk->header) - top_split_sz;

            size_t save_old_bits = *old_header & 0x7; 
            *old_header = top_split_sz | save_old_bits;
            *old_header &= ~THIS_BLOCK_ALLOCATED;

            sf_block *old_blk = (sf_block *)((void *)old_header);
            sf_footer *blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(old_blk);
            *blk_ftr_ptr = *old_header;
            push_front_free_lst(old_blk);

            size_t remainder_bottom = remainder_from_top - SET_DEFAULT_PAD_SIZE(size);
            sf_block *new_blk = (sf_block *)((void *)new_header);
            if(remainder_bottom < BLK_SIZE_MIN) {
                // don't split bottom
                *new_header = remainder_from_top | THIS_BLOCK_ALLOCATED;
                set_nxt_prv_a(new_blk);
            } else {
                *new_header = SET_DEFAULT_PAD_SIZE(size) | THIS_BLOCK_ALLOCATED;
                sf_block *bottom_split_f_blk = (sf_block *)GET_ADJ_NXT_BLK(new_blk);
                bottom_split_f_blk->header = remainder_bottom | PREV_BLOCK_ALLOCATED;
                sf_footer *bottom_split_f_blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(bottom_split_f_blk);
                *bottom_split_f_blk_ftr_ptr = bottom_split_f_blk->header;

                bottom_split_f_blk->body.links.next = NULL;
                bottom_split_f_blk->body.links.prev = NULL;

                push_front_free_lst(bottom_split_f_blk);
                clear_nxt_prv_a(bottom_split_f_blk);
                
                coalesce(bottom_split_f_blk);
            }
            coalesce(old_blk);
            ret = new_payload_ptr;
        } else {
            ret = &(qk_blk->body.payload);
        }
    } else {
        void *start_ptr = sf_mem_start();
        void *end_ptr = sf_mem_end();

        if(start_ptr == end_ptr) {
            void *heap_ptr = sf_mem_grow(); 
            if(heap_ptr == NULL) {
                sf_errno = ENOMEM;
                return NULL;
            }
            end_ptr = sf_mem_end();
            PROLOGUE_PTR = (sf_block *)start_ptr;
            PROLOGUE_PTR->header |= THIS_BLOCK_ALLOCATED;
            PROLOGUE_PTR->header |= BLK_SIZE_MIN; // set size to 32

            //EPILOGUE_PTR = (sf_header *)(end_ptr - WORD_SIZE_ALIGN);
            SET_NEW_EPILOGUE(end_ptr - WORD_SIZE_ALIGN);
            *EPILOGUE_PTR |= THIS_BLOCK_ALLOCATED;  

            size_t first_free_blk_size = PAGE_SZ - GET_BLK_HDR_SZ(PROLOGUE_PTR->header) - sizeof(sf_header); 

            sf_block *first_free_blk_ptr = ((void *)PROLOGUE_PTR) + GET_BLK_HDR_SZ(PROLOGUE_PTR->header);

            first_free_blk_ptr->header = first_free_blk_size;
            first_free_blk_ptr->header |= PREV_BLOCK_ALLOCATED;

            sf_footer *first_ftr_ptr = (((void *)first_free_blk_ptr) + GET_BLK_HDR_SZ(first_free_blk_ptr->header)) - sizeof(sf_footer);

            *first_ftr_ptr = first_free_blk_ptr->header; 

            initialize_free_lists();
            push_front_free_lst(first_free_blk_ptr);
        }

        sf_block *fb = NULL;
        while(fb == NULL) {
            fb = find_first_fit(allocated_size);
            if(fb == NULL) {
                void *old_end_ptr = sf_mem_grow();
                if(old_end_ptr == NULL) {
                    sf_errno = ENOMEM;
                    return NULL;
                }
                sf_header *old_epilogue_hdr = EPILOGUE_PTR; 
                SET_NEW_EPILOGUE(sf_mem_end() - WORD_SIZE_ALIGN);
                *EPILOGUE_PTR |= THIS_BLOCK_ALLOCATED; 

                sf_block *new_sf_block = (sf_block *)old_epilogue_hdr;
                new_sf_block->header |= PAGE_SZ;
                new_sf_block->header &= ~THIS_BLOCK_ALLOCATED;

                sf_footer *ftr_ptr = (sf_footer *)GET_BLK_FTR(new_sf_block);
                *ftr_ptr = new_sf_block->header;

                push_front_free_lst(new_sf_block);
                coalesce(new_sf_block);
            }
        }
        void *old_payload_ptr  = (void *)(fb) + sizeof(sf_header);
        if(((size_t)old_payload_ptr) % align) {
            remove_blk_from_lst(fb);

            sf_header *old_header = (sf_header *)(old_payload_ptr - WORD_SIZE_ALIGN);
            // guaranteed that the remainder 
            void *new_payload_ptr = (void *)pad_size((size_t)(old_payload_ptr + BLK_SIZE_MIN), align);
            sf_header *new_header = (sf_header *)(new_payload_ptr - WORD_SIZE_ALIGN);

            // splitting top split here
            size_t top_split_sz = (void *)new_header - (void *)old_header;

            size_t remainder_from_top = GET_BLK_HDR_SZ(fb->header) - top_split_sz;

            /* add back the top split to free list*/
            size_t save_old_bits = *old_header & 0x7; 
            *old_header = top_split_sz | save_old_bits;
            sf_block *old_blk = (sf_block *)((void *)old_header);
            sf_footer *blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(old_blk);
            *blk_ftr_ptr = *old_header;
            push_front_free_lst(old_blk);

            // don't need to bit set prev alloc since prev alloc is free

            size_t remainder_bottom = remainder_from_top - SET_DEFAULT_PAD_SIZE(size);
            sf_block *new_blk = (sf_block *)((void *)new_header);
            if(remainder_bottom < BLK_SIZE_MIN) {
                // don't split bottom
                *new_header = remainder_from_top | THIS_BLOCK_ALLOCATED;
                set_nxt_prv_a(new_blk);
            } else {
                *new_header = SET_DEFAULT_PAD_SIZE(size) | THIS_BLOCK_ALLOCATED;
                sf_block *bottom_split_f_blk = (sf_block *)GET_ADJ_NXT_BLK(new_blk);
                bottom_split_f_blk->header = remainder_bottom | PREV_BLOCK_ALLOCATED;
                sf_footer *bottom_split_f_blk_ftr_ptr = (sf_footer *)GET_BLK_FTR(bottom_split_f_blk);
                *bottom_split_f_blk_ftr_ptr = bottom_split_f_blk->header;

                bottom_split_f_blk->body.links.next = NULL;
                bottom_split_f_blk->body.links.prev = NULL;

                push_front_free_lst(bottom_split_f_blk);
                clear_nxt_prv_a(bottom_split_f_blk);
                
                coalesce(bottom_split_f_blk);
            }
            coalesce(old_blk);
            ret = new_payload_ptr;
        } else {
            allocate_and_split_block(fb, allocated_size);
            ret = &(fb->body.payload);
        }
    }
    return ret;
}
