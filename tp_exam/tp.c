/* GPLv2 (c) Airbus */
#include <debug.h>
#include <segmem.h>
#include <pagemem.h>
#include <string.h>
#include <cr.h>
#include <intr.h>
#include <info.h>
#include <asm.h>
#include <io.h>

#define tss_dsc(_dSc_,_tSs_)                                            \
   ({                                                                   \
      raw32_t addr    = {.raw = _tSs_};                                 \
      (_dSc_)->raw    = sizeof(tss_t);                                  \
      (_dSc_)->base_1 = addr.wlow;                                      \
      (_dSc_)->base_2 = addr._whigh.blow;                               \
      (_dSc_)->base_3 = addr._whigh.bhigh;                              \
      (_dSc_)->type   = SEG_DESC_SYS_TSS_AVL_32;                        \
      (_dSc_)->p      = 1;                                              \
   })


seg_desc_t my_gdt[6];
tss_t TSS;

void set_segmentation_routine(){
    
	//Empty first
    my_gdt[0].raw = 0ULL;
	// Kernel code seg : 1
    my_gdt[1].limit_1 = 0xffff;   //:16;     /* bits 00-15 of the segment limit */
    my_gdt[1].base_1 = 0x0000;    //:16;     /* bits 00-15 of the base address */
    my_gdt[1].base_2 = 0x00;      //:8;      /* bits 16-23 of the base address */
    my_gdt[1].type = 11;//Code,RX //:4;      /* segment type */
    my_gdt[1].s = 1;              //:1;      /* descriptor type */
    my_gdt[1].dpl = 0; //ring0    //:2;      /* descriptor privilege level */
    my_gdt[1].p = 1;              //:1;      /* segment present flag */
    my_gdt[1].limit_2 = 0xf;      //:4;      /* bits 16-19 of the segment limit */
    my_gdt[1].avl = 1;            //:1;      /* available for fun and profit */
    my_gdt[1].l = 0; //32bits     //:1;      /* longmode */
    my_gdt[1].d = 1;              //:1;      /* default length, depend on seg type */
    my_gdt[1].g = 1;              //:1;      /* granularity */
    my_gdt[1].base_3 = 0x00;      //:8;      /* bits 24-31 of the base address */
	// Kernel data seg: 2
    my_gdt[2].limit_1 = 0xffff;   //:16;     /* bits 00-15 of the segment limit */
    my_gdt[2].base_1 = 0x0000;    //:16;     /* bits 00-15 of the base address */
    my_gdt[2].base_2 = 0x00;      //:8;      /* bits 16-23 of the base address */
    my_gdt[2].type = 3; //data,RW //:4;      /* segment type */
    my_gdt[2].s = 1;              //:1;      /* descriptor type */
    my_gdt[2].dpl = 0; //ring0    //:2;      /* descriptor privilege level */
    my_gdt[2].p = 1;              //:1;      /* segment present flag */
    my_gdt[2].limit_2 = 0xf;      //:4;      /* bits 16-19 of the segment limit */
    my_gdt[2].avl = 1;            //:1;      /* available for fun and profit */
    my_gdt[2].l = 0; // 32 bits   //:1;      /* longmode */
    my_gdt[2].d = 1;              //:1;      /* default length, depend on seg type */
    my_gdt[2].g = 1;              //:1;      /* granularity */
    my_gdt[2].base_3 = 0x00;      //:8;      /* bits 24-31 of the base address */
	// Userland code seg: 3
    my_gdt[3].limit_1 = 0xffff;   //:16;     /* bits 00-15 of the segment limit */
    my_gdt[3].base_1 = 0x0000;    //:16;     /* bits 00-15 of the base address */
    my_gdt[3].base_2 = 0x00;      //:8;      /* bits 16-23 of the base address */
    my_gdt[3].type = 11; //data,RW //:4;      /* segment type */
    my_gdt[3].s = 1;              //:1;      /* descriptor type */
    my_gdt[3].dpl = 3; //ring3    //:2;      /* descriptor privilege level */
    my_gdt[3].p = 1;              //:1;      /* segment present flag */
    my_gdt[3].limit_2 = 0xf;      //:4;      /* bits 16-19 of the segment limit */
    my_gdt[3].avl = 1;            //:1;      /* available for fun and profit */
    my_gdt[3].l = 0; // 32 bits   //:1;      /* longmode */
    my_gdt[3].d = 1;              //:1;      /* default length, depend on seg type */
    my_gdt[3].g = 1;              //:1;      /* granularity */
    my_gdt[3].base_3 = 0x00;      //:8;      /* bits 24-31 of the base address */
	// Userland data seg: 4
    my_gdt[4].limit_1 = 0xffff;   //:16;     /* bits 00-15 of the segment limit */
    my_gdt[4].base_1 = 0x0000;    //:16;     /* bits 00-15 of the base address */
    my_gdt[4].base_2 = 0x00;      //:8;      /* bits 16-23 of the base address */
    my_gdt[4].type = 3; //data,RW //:4;      /* segment type */
    my_gdt[4].s = 1;              //:1;      /* descriptor type */
    my_gdt[4].dpl = 3; //ring3    //:2;      /* descriptor privilege level */
    my_gdt[4].p = 1;              //:1;      /* segment present flag */
    my_gdt[4].limit_2 = 0xf;      //:4;      /* bits 16-19 of the segment limit */
    my_gdt[4].avl = 1;            //:1;      /* available for fun and profit */
    my_gdt[4].l = 0; // 32 bits   //:1;      /* longmode */
    my_gdt[4].d = 1;              //:1;      /* default length, depend on seg type */
    my_gdt[4].g = 1;              //:1;      /* granularity */
    my_gdt[4].base_3 = 0x00;      //:8;      /* bits 24-31 of the base address */

	//Set gdt and selectors

	gdt_reg_t my_gdtr;
    my_gdtr.addr = (long unsigned int)my_gdt;
    my_gdtr.limit = sizeof(my_gdt) - 1;
    set_gdtr(my_gdtr);

    set_cs(gdt_krn_seg_sel(1));
    
    set_ss(gdt_krn_seg_sel(2));
    set_ds(gdt_krn_seg_sel(2));
    set_es(gdt_krn_seg_sel(2));
    set_fs(gdt_krn_seg_sel(2));
    set_gs(gdt_krn_seg_sel(2));

	//create TSS
    TSS.s0.esp = get_ebp();
    TSS.s0.ss  = gdt_krn_seg_sel(2);
    tss_dsc(&my_gdt[5], (offset_t)&TSS);
    set_tr(gdt_krn_seg_sel(5));

}

void print_gdt_content(gdt_reg_t gdtr_ptr) {
    seg_desc_t* gdt_ptr;
    gdt_ptr = (seg_desc_t*)(gdtr_ptr.addr);
    int i=0;
    while ((uint32_t)gdt_ptr < ((gdtr_ptr.addr) + gdtr_ptr.limit)) {
        uint32_t start = gdt_ptr->base_3<<24 | gdt_ptr->base_2<<16 | gdt_ptr->base_1;
        uint32_t end;
        if (gdt_ptr->g) {
            end = start + ( (gdt_ptr->limit_2<<16 | gdt_ptr->limit_1) <<12) + 4095;
        } else {
            end = start + (gdt_ptr->limit_2<<16 | gdt_ptr->limit_1);
        }
        debug("%d ", i);
        debug("[0x%x ", start);
        debug("- 0x%x] ", end);
        debug("seg_t: 0x%x ", gdt_ptr->type);
        debug("desc_t: %d ", gdt_ptr->s);
        debug("priv: %d ", gdt_ptr->dpl);
        debug("present: %d ", gdt_ptr->p);
        debug("avl: %d ", gdt_ptr->avl);
        debug("longmode: %d ", gdt_ptr->l);
        debug("default: %d ", gdt_ptr->d);
        debug("gran: %d ", gdt_ptr->g);
        debug("\n");
        gdt_ptr++;
        i++;
    }
}


void syscall_isr() {
   asm volatile (
      "cli                  \n"
      "leave ; pusha        \n"
      "mov %esp, %eax      \n"
      "call syscall_handler \n"
      "popa ; iret"
      );
}

void __regparm__(1) syscall_handler(int_ctx_t *ctx) {
	uint32_t eax = ctx->gpr.eax.raw;
	uint32_t * counter = (uint32_t*)eax;
	debug("Counter value: %u\n", *counter);
    outb(0x80, 0x80);
}

pde32_t *pgd = (pde32_t*)0x600000; // 00 0000 0001   -- 10 0000 0000   -- 0000 0000 0000
pte32_t *ptb = (pte32_t*)0x601000;

pde32_t *pgd1 = (pde32_t*)0x700000;
pte32_t *ptb1 = (pte32_t*)0x701000;
pte32_t *ptb2 = (pte32_t*)0x702000;
pte32_t *ptb3 = (pte32_t*)0x703000;

// PAGES BEGIN

void set_pages_routine(){

	memset((void*)pgd, 0, PAGE_SIZE);

    memset((void*)ptb, 0, PAGE_SIZE);


    memset((void*)pgd1, 0, PAGE_SIZE);

    memset((void*)ptb1, 0, PAGE_SIZE);
    memset((void*)ptb2, 0, PAGE_SIZE);
    memset((void*)ptb3, 0, PAGE_SIZE);


    for(int i=0;i<1024;i++) 
	{
	 	pg_set_entry(&ptb[i], PG_KRN|PG_RW, i);
	 	pg_set_entry(&ptb1[i], PG_KRN|PG_RW, i);

		pg_set_entry(&ptb2[i], PG_USR|PG_RW, 1024 + i); 
	}

    pg_set_entry(&ptb3[0], PG_USR|PG_RW, 0xe00000 >> 12);

	pg_set_entry(&pgd[0], PG_KRN|PG_RW, page_get_nr(ptb));


	pg_set_entry(&pgd1[0], PG_KRN|PG_RW, page_get_nr(ptb1));

	pg_set_entry(&pgd1[1], PG_USR|PG_RW, page_get_nr(ptb2)); 

	pg_set_entry(&pgd1[2], PG_USR|PG_RW, page_get_nr(ptb3));

    set_cr3((uint32_t)pgd);     

    uint32_t cr0 = get_cr0();
	set_cr0(cr0|CR0_PG);

}

// PAGES END

void set_interrupt_routine(){
   idt_reg_t idtr;
   get_idtr(idtr);
   debug("IDT @ 0x%x\n", (unsigned int) idtr.addr);

   int_desc_t *dsc;
   dsc = &idtr.desc[0x80];
   dsc->dpl = 0x3;
   dsc->offset_1 = (uint16_t)((uint32_t)syscall_isr); // 3 install kernel syscall handler
   dsc->offset_2 = (uint16_t)(((uint32_t)syscall_isr)>>16);
}

// END INTERRUPT

struct task {
    void *function;
    uint32_t stack;
    uint32_t interrupt_stack;
    pde32_t *pgd;
    int_ctx_t context;
};


__attribute__ ((section(".task_code")))
void foo()
{
	uint32_t * counter = (uint32_t*)0x800000;
	*counter=0;
	while(1)
	{
		*counter = *counter + 1;
	}
}


#define STACK_SIZE 4096
#define INTERRUPT_STACK_SIZE 4096
#define INTERRUPT_STACK_TASK_1 0x380000

uint32_t task1_stack[STACK_SIZE] __attribute__((aligned(4), section(".task1_stack")));


struct task task1;

void tp() {
	set_segmentation_routine();
    set_pages_routine();
    set_interrupt_routine();


    task1.function = &foo;
    task1.pgd = pgd1;
    task1.stack = (uint32_t)&task1_stack[STACK_SIZE-1];
    memset(&task1.context, 0, sizeof(int_ctx_t));
    task1.interrupt_stack = INTERRUPT_STACK_TASK_1 + INTERRUPT_STACK_SIZE;
    set_ds(gdt_usr_seg_sel(4));
    set_es(gdt_usr_seg_sel(4));
    set_fs(gdt_usr_seg_sel(4));
    set_gs(gdt_usr_seg_sel(4));

    TSS.s0.esp = task1.interrupt_stack;

	set_cr3((uint32_t)task1.pgd); //set page here but still page fault, not sure why
    debug("PLS WORK WORK WORK \n\n\n\n\n\n");

    asm volatile(
			"sti \n"
			"push %0 \n" // ss
			"push %1 \n" // esp
			"pushf   \n" // eflags
			"push %2 \n" // cs
			"push %3 \n" // eip
			::"i"(gdt_usr_seg_sel(4)),
			"m"(task1.stack),
			"i"(gdt_usr_seg_sel(3)),
			"r"(task1.function));
		asm volatile("sti ; iret");

	gdt_reg_t gdtr_ptr;
    get_gdtr(gdtr_ptr);
	print_gdt_content(gdtr_ptr);

}
