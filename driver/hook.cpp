#include "hook.h"
BOOL pysenhook::CallKernelFunction(void* kernel_function_addr)
{
	
	if (!kernel_function_addr)
		return FALSE;
	PVOID* function = reinterpret_cast<PVOID*>(GetSystemModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys","NtQueryCompositionSurfaceStatistics"));
	if (!function)
		return FALSE;
	BYTE orig[] = { 0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00,0x00 ,0x00 ,0x00 ,0x00 }; 
	BYTE shellcode[] = { 0x48,0xB8 };// mov rax,xxx
	BYTE shellcode_end[] = {0xFF,0xE0};// jmp rax
	RtlSecureZeroMemory(&orig,sizeof(orig));
	memcpy((PVOID)(ULONG_PTR)orig,&shellcode,sizeof(shellcode));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_addr);
	memcpy((PVOID)((ULONG_PTR)orig+sizeof(shellcode)),&hook_address,sizeof(void*)); 
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shellcode) + sizeof(void*)), &shellcode_end, sizeof(shellcode_end));
	WriteReadOnlyMemory(function,&orig,sizeof(orig));
	return TRUE;
}
NTSTATUS pysenhook::HookHandler(PVOID call_param)
{
	

	if (!MmIsAddressValid(call_param))
	{
		
		return STATUS_SUCCESS;
	}
	PNULL_MEMORY pParam = (PNULL_MEMORY)call_param;
	switch (pParam->instruction)
	{
	case READ_PROCESS_MEMORY:
		myReadProcessMemory((HANDLE)pParam->pid,(PVOID)pParam->address,pParam->buffer_address,pParam->size);
		break;
	case WRITE_PROCESS_MEMORY:
		myWriteProcessMemory((HANDLE)pParam->pid, (PVOID)pParam->address, pParam->buffer_address, pParam->size);
		break;
	case ALLOCATE_MEMORY:
		pParam->allocate_base = AllocateVirtualMemory((HANDLE)pParam->pid,pParam->size,pParam->protect);
		break;
	case FREE_MEMORY:
		FreeVirtualMemory((HANDLE)pParam->pid,pParam->allocate_base);
		break;
	case PROTECT_MEMORY:
		ProtectVirtualMemory((HANDLE)pParam->pid,pParam->address,pParam->size,pParam->protect);
		break;
	case OPEN_PROCESS:
		pParam->buffer_address = GetProcessHandle((HANDLE)pParam->pid);
		break;
	case WRITE_PROCESS_MEMORY64:
		myWriteProcessMemory64((HANDLE)pParam->pid, (PVOID)pParam->address64, pParam->buffer_address64, pParam->size);
		break;
	case READ_PROCESS_MEMORY64:
		myReadProcessMemory64((HANDLE)pParam->pid, (PVOID)pParam->address64, pParam->buffer_address64, pParam->size);
		break;
		
	default:
		break;
	}

	
	return STATUS_SUCCESS;
}
