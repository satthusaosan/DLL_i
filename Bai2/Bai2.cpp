#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include<processthreadsapi.h>
#include<TlHelp32.h>
#include <codecvt>
using namespace std;

DWORD MyGetProcessID(LPCWSTR ProcessName) {
	PROCESSENTRY32 pt;

	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pt.dwSize = sizeof(PROCESSENTRY32); //phai viet trc Process32First

	if (Process32First(hsnap, &pt)) { // tim tien trinh dau tien
		do
		{
			if (!lstrcmp(pt.szExeFile, ProcessName)) {//
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));// tien trinh tiep theo

	}

	CloseHandle(hsnap);

	return 0;
}

int main(int argc, char** argv) {

	//L?y PID c?a process c?n inject
	/*uint16_t target_pid;
	std::string pid_str;
	std::cout << "\nEnter target process ID: ";
	std::getline(std::cin, pid_str);
	target_pid = stoi(pid_str);*/

	cout << "let get ID of a process" << endl;
	cout << "name process: ";
	string name;
	cin >> name;
	wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	wstring wide = converter.from_bytes(name);                  // conver string to wstring

	uint16_t target_pid = MyGetProcessID(wide.c_str());

	if (!target_pid) {
		std::cerr << "Get remote  process ID failed" << std::endl;
		return 1;
	}
	cout << "process ID:" << target_pid << endl;
	// L?y du?ng d?n d?n DLL mà ta mu?n inject
	std::string dll_path;
	std::cout << "Enter path to DLL: ";
	//std::getline(std::cin, dll_path);
	cin >> dll_path;
	std::cout << "DLL path: " << dll_path << std::endl;

	// L?y handle c?a remote process

	HANDLE target_process = OpenProcess(PROCESS_ALL_ACCESS, 
										FALSE, 
										target_pid);



	std::cout << "Handle of target process: " << target_process << std::endl;
	if (target_process == NULL) {
		std::cerr << "Get handle to remote target process failed" << std::endl;
		return 1;
	}

	// C?p phát vùng nh? cho dll path trong target process

	LPVOID dll_path_in_remote_mem_addr = VirtualAllocEx(
		target_process,
		NULL,
		_MAX_PATH,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	);

	if (dll_path_in_remote_mem_addr == NULL) {
		std::cerr << "Allocate space for  DLL path in  remote  process failed..." << std::endl;
		CloseHandle(target_process);
		return 1;
	}

	std::cout << "DLL allocation memory address in remote process: " << dll_path_in_remote_mem_addr << std::endl;
	// Copy  DLL path vào vùng nh? du?c c?p phát


	bool write_status = WriteProcessMemory(
		target_process,
		dll_path_in_remote_mem_addr,
		dll_path.c_str(),
		strlen(dll_path.c_str()),
		NULL
	);

	std::cout << "WriteProcessMemory was " << (write_status ? "successful!" : "unsuccessful...") << std::endl;;

	if (!write_status) {
		std::cerr << "GetLastError() for failed WriteProcessMemory() call: " << GetLastError() << std::endl;
		CloseHandle(target_process);
		return 1;
	}

	// L?y d?a ch? c?a LoadLibraryA 
	LPVOID load_library_addr = (LPVOID)GetProcAddress(
		GetModuleHandle(TEXT("kernel32.dll")),
		"LoadLibraryA"
	);

	if (load_library_addr == NULL) {
		std::cerr << "GetProcAddress failed..." << std::endl;
		CloseHandle(target_process);
		return 1;
	}

	std::cout << "LoadLibraryA address in remote process: " << load_library_addr << std::endl;
	// T?o remote thread d? ch?y dll
	HANDLE remote_thread = CreateRemoteThread(
		target_process,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)load_library_addr,
		dll_path_in_remote_mem_addr,
		NULL,
		NULL
	);

	if (remote_thread == NULL) {
		std::cerr << "CreateRemoteThread failed..." << std::endl;
		return 1;
	}
	//std::cout << "waitForSingleObject: " << WaitForSingleObject(remote_thread, INFINITE) << std::endl;
	//std::cout << "Remote thread address: " << &remote_thread << std::endl;
	std::cout << "Handle of remote thread: " << remote_thread << std::endl;
	// Ðóng remote thread handle và gi?i phóng vùng nh? dã c?p phát kh?i target process
	if (VirtualFreeEx(target_process, dll_path_in_remote_mem_addr, 0, MEM_RELEASE) == 0) {
		std::cerr << "VirtualFreeEx failed on target process" << std::endl;
	}

	// Gi?i phóng handle c?a remote thread
	CloseHandle(remote_thread);

	// Gi?i phóng handle c?a remote process
	CloseHandle(target_process);

	std::cout << "Press any key to exit" << std::endl;
	std::cin.get();

	return 0;
}





