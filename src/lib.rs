#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![feature(pointer_byte_offsets)]
extern crate alloc;
mod wrappers;
mod writer;
use alloc::{
    alloc::{alloc, dealloc},
    vec::Vec,
};
use core::{
    alloc::{GlobalAlloc, Layout},
    mem,
    panic::PanicInfo,
    ptr,
};
use iced_x86::{
    code_asm::{eax, CodeAssembler},
    Decoder,
};

use wrappers::{alloc_console, free_console};

use winapi::{
    ctypes::c_void,
    shared::{
        minwindef::{PULONG, ULONG},
        ntdef::{HANDLE, NTSTATUS, PVOID},
        ntstatus::STATUS_UNSUCCESSFUL,
    },
    um::{
        handleapi::CloseHandle,
        heapapi::{GetProcessHeap, HeapAlloc, HeapFree, HeapReAlloc},
        libloaderapi::{FreeLibraryAndExitThread, GetModuleHandleA, GetProcAddress},
        memoryapi::{VirtualAlloc, VirtualFree},
        processthreadsapi::{CreateThread, GetCurrentProcessId},
        synchapi::Sleep,
        winnt::{
            DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, HEAP_ZERO_MEMORY, MEM_COMMIT, MEM_RELEASE,
            PAGE_READWRITE,
        },
        winuser::{GetAsyncKeyState, VK_END},
    },
};
#[cfg(not(test))]
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> !
{
    // zzzzzzzzzz mimimimimi

    loop
    {}
}

#[cfg(not(test))]
#[alloc_error_handler]
fn alloc_error_handler(_: Layout) -> !
{
    // zzzzzzzzzz mimimimimi

    loop
    {}
}
pub struct HeapAllocator;

unsafe impl GlobalAlloc for HeapAllocator
{
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8
    {
        HeapAlloc(GetProcessHeap(), 0, _layout.size()) as *mut u8
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8
    {
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, layout.size()) as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout)
    {
        HeapFree(GetProcessHeap(), 0, _ptr as *mut c_void);
    }

    unsafe fn realloc(&self, ptr: *mut u8, _layout: Layout, new_size: usize) -> *mut u8
    {
        HeapReAlloc(
            GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            ptr as *mut c_void,
            new_size,
        ) as *mut u8
    }
}

#[global_allocator]
static GLOBAL: HeapAllocator = HeapAllocator;

#[repr(C)]
#[derive(Debug)]
struct SystemHandleInformation
{
    handle_count: u32,
    handles:      [SystemHandle; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct SystemHandle
{
    process_id:     u32,
    objtype:        u8,
    flags:          u8,
    handle:         u16,
    object:         *mut c_void,
    granted_access: u32,
}

type FnQuerySystemInfo = unsafe extern "system" fn(u8, PVOID, ULONG, PULONG) -> NTSTATUS;
type FnQueryObject = unsafe extern "system" fn(HANDLE, u8, PVOID, ULONG, PULONG) -> NTSTATUS;
fn query_system_info(
    SystemInformationClass: u8, SystemInformation: PVOID, SystemInformationLength: ULONG,
    ReturnLength: PULONG,
) -> NTSTATUS
{
    let func: FnQuerySystemInfo = unsafe {
        mem::transmute(GetProcAddress(
            GetModuleHandleA(b"ntdll.dll\0".as_ptr() as _) as _,
            b"NtQuerySystemInformation\0".as_ptr() as _,
        ))
    };
    unsafe {
        func(
            SystemInformationClass,
            SystemInformation,
            SystemInformationLength,
            ReturnLength,
        )
    }
}
fn find_handles(pid: u32) -> Vec<usize>
{
    let mut ntstatus: u32 = STATUS_UNSUCCESSFUL as _;
    let mut buffer: PVOID = ptr::null_mut();

    let mut size = 0u32;

    let mut result = Vec::<usize>::new();
    loop
    {
        ntstatus =
            unsafe { query_system_info(16, buffer, size as _, ptr::addr_of_mut!(size) as _) } as _;

        if ntstatus != 0
        {
            if ntstatus == 0xC0000004
            // STATUS_INFO_LENGTH_MISMATCH
            {
                if !buffer.is_null()
                {
                    unsafe {
                        VirtualFree(buffer, 0, MEM_RELEASE);
                    }
                }
                buffer =
                    unsafe { VirtualAlloc(ptr::null_mut(), size as _, MEM_COMMIT, PAGE_READWRITE) };
                continue;
            }

            break;
        }
        else
        {
            let handleinfo: *mut SystemHandleInformation = buffer as _;
            minicrt_println!("handle: {:?}", handleinfo);
            for idx in 0..unsafe { handleinfo.read().handle_count }
            {
                if handleinfo.is_null()
                {
                    continue;
                }
                let ptr = unsafe { handleinfo.byte_add(4) as *mut usize };
                let handle: *mut SystemHandle = unsafe {
                    mem::transmute(ptr.byte_add(mem::size_of::<SystemHandle>() * idx as usize))
                };

                if unsafe { handle.read().process_id } == pid
                    && unsafe { handle.read().objtype } == 7
                {
                    minicrt_println!("found intended handle! {:?}", unsafe { handle.read() });
                    result.push(unsafe { handle.read().handle } as _);
                }
            }
            break;
        }
    }

    if !buffer.is_null()
    {
        unsafe {
            VirtualFree(buffer, 0, MEM_RELEASE);
        };
    }

    result
}

unsafe extern "system" fn init(module: *mut c_void) -> u32
{
    let pid = GetCurrentProcessId();
    minicrt_println!("inside pid: {pid}, searching handles...");
    let res = find_handles(pid as _);

    if res.is_empty()
    {
        minicrt_println!("no handles found :(");
    }
    else
    {
        minicrt_println!("Found handles: {:#x?}", res);
    }

    loop
    {
        if GetAsyncKeyState(VK_END) != 0
        {
            FreeLibraryAndExitThread(module as _, 0);
            break;
        }
        Sleep(50);
    }
    0
}
pub unsafe extern "system" fn terminate() -> u32
{
    free_console();
    1
}

#[no_mangle]
unsafe extern "system" fn _DllMainCRTStartup(module: *const u8, reason: u32, _: *const u8) -> u32
{
    match reason
    {
        DLL_PROCESS_ATTACH =>
        {
            let handle = CreateThread(
                ptr::null_mut(),
                0,
                Some(init),
                module as *mut _,
                0,
                ptr::null_mut(),
            );
            if !handle.is_null()
            {
                CloseHandle(handle);
            }
        }
        DLL_PROCESS_DETACH =>
        {
            terminate();
        }
        _ =>
        {}
    }
    1
}
