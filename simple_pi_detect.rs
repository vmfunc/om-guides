// https://om.malcore.io/t/detecting-pi-with-memory-scanning-windows

extern crate winapi;

use std::mem::{size_of, zeroed};
use std::ptr::null_mut;
use winapi::shared::minwindef::{DWORD, HMODULE, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{EnumProcessModules, EnumProcesses, GetModuleInformation, MODULEINFO};
use winapi::um::winnt::{
    HANDLE, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

fn main() {
    unsafe {
        const MAX_PROCESSES: usize = 1024;
        let mut process_ids = vec![0u32; MAX_PROCESSES];
        let mut bytes_returned = 0u32;

        if EnumProcesses(
            process_ids.as_mut_ptr(),
            (MAX_PROCESSES * size_of::<DWORD>()) as u32,
            &mut bytes_returned,
        ) == 0
        {
            println!("EnumProcesses failed: {}", GetLastError());
            return;
        }

        let num_processes = bytes_returned as usize / size_of::<DWORD>();

        for i in 0..num_processes {
            let pid = process_ids[i];
            scan_process(pid);
        }
    }
}

unsafe fn scan_process(pid: DWORD) {
    let process_handle: HANDLE = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if process_handle.is_null() {
        return;
    }

    const MAX_MODULES: usize = 1024;
    let mut module_handles = vec![0 as HMODULE; MAX_MODULES];
    let mut cb_needed = 0u32;

    if EnumProcessModules(
        process_handle,
        module_handles.as_mut_ptr(),
        (MAX_MODULES * size_of::<HMODULE>()) as u32,
        &mut cb_needed,
    ) == 0
    {
        // cannot enum modules
    }

    let num_modules = (cb_needed as usize) / size_of::<HMODULE>();
    let mut module_regions = Vec::new();

    for i in 0..num_modules {
        let h_module = module_handles[i];
        let mut module_info: MODULEINFO = zeroed();
        if GetModuleInformation(
            process_handle,
            h_module,
            &mut module_info,
            size_of::<MODULEINFO>() as u32,
        ) == 0
        {
            continue;
        }
        let base_of_dll = module_info.lpBaseOfDll;
        let size_of_image = module_info.SizeOfImage;

        module_regions.push((base_of_dll as usize, size_of_image as usize));
    }

    let mut address = 0 as LPVOID;
    loop {
        let mut mbi: MEMORY_BASIC_INFORMATION = zeroed();
        let result = VirtualQueryEx(
            process_handle,
            address,
            &mut mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        if result == 0 {
            break;
        }

        // if committed + X
        if (mbi.State == MEM_COMMIT)
            && ((mbi.Protect == PAGE_EXECUTE_READWRITE) || (mbi.Protect == PAGE_EXECUTE_READ))
        {
            let mem_start = mbi.BaseAddress as usize;
            let mem_end = mem_start + mbi.RegionSize;

            // presence in any module
            let mut in_module = false;
            for &(module_base, module_size) in &module_regions {
                let module_start = module_base;
                let module_end = module_start + module_size;

                if (mem_start >= module_start) && (mem_start < module_end) {
                    in_module = true;
                    break;
                }
            }

            if !in_module {
                println!("suspicious region in {} at 0x{:X}", pid, mem_start);
            }
        }

        address = (address as usize + mbi.RegionSize) as LPVOID;
    }

    CloseHandle(process_handle);
}
