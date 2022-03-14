use rmm_core::io::{stdout, Write as IoWrite};
use rmm_core::println;

use crate::aarch64;
use crate::allocator;
use crate::config::{MAX_VCPUS, NUM_OF_CPU, PRIMARY_VM_ID, RMM_STACK_SIZE};
use crate::realm::vm::{VM, VMS};
use alloc::sync::Arc;
use spin::Mutex;

extern crate alloc;

#[no_mangle]
#[link_section = ".stack"]
static mut RMM_STACK: [u8; RMM_STACK_SIZE * NUM_OF_CPU] = [0; RMM_STACK_SIZE * NUM_OF_CPU];

#[naked]
#[link_section = ".head.text"]
#[no_mangle]
unsafe extern "C" fn rmm_entry() {
    #![allow(unsupported_naked_functions)]
    llvm_asm! {
        "
        msr spsel, #1
        bl get_cpu_id

        ldr x1, =__RMM_STACK_END__
        mov x2, $0
        mul x0, x0, x2
        sub x0, x1, x0
        mov sp, x0

        bl setup

        1:
        bl main
        b 1b
        "
        : : "i"(RMM_STACK_SIZE): : "volatile"
    }
}

extern "C" {
    static __BSS_START__: usize;
    static __BSS_SIZE__: usize;
}

unsafe fn clear_bss() {
    let bss = core::slice::from_raw_parts_mut(
        &__BSS_START__ as *const usize as *mut u64,
        &__BSS_SIZE__ as *const usize as usize / core::mem::size_of::<u64>(),
    );
    bss.fill(0);
}

fn init_console() {
    let _ = stdout().attach(crate::driver::uart::pl011::device());

    println!("RMM: initialized the console!");
}

#[no_mangle]
#[allow(unused)]
unsafe fn setup() {
    static mut COLD_BOOT: bool = true;

    if (&COLD_BOOT as *const bool).read_volatile() {
        clear_bss();
        allocator::init();
        init_console();

        let mut primary_vm = VM::uninitialized();
        primary_vm.initialize(PRIMARY_VM_ID, MAX_VCPUS);

        VMS.push(Arc::new(Mutex::new(primary_vm)));

        (&mut COLD_BOOT as *mut bool).write_volatile(false);
    }

    aarch64::init();
}